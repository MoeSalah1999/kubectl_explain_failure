from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class RuntimeFailureBurstRule(FailureRule):
    """
    Detects runtime startup failures that briefly recover and then recur.

    Real-world behavior:
    - kubelet/runtime instability can cause an initial container start failure,
      a brief successful `Started` transition, and then another runtime start
      failure shortly after
    - Kubernetes may coalesce repeated failure attempts into one event via
      `count`, `firstTimestamp`, and `lastTimestamp`, so a burst must account
      for event-episode boundaries and total attempts
    - this is more specific than a one-off runtime start failure because it
      proves transient recovery between repeated runtime failures
    """

    name = "RuntimeFailureBurst"
    category = "Temporal"
    priority = 84
    deterministic = False

    phases = ["Pending", "Running", "Unknown"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ContainerRuntimeStartFailure",
    ]

    WINDOW_MINUTES = 20
    MAX_PATTERN_SPAN = timedelta(minutes=15)
    MIN_FAILURE_OCCURRENCES = 2

    WAITING_REASONS = {
        "ContainerCreating",
        "CreateContainerError",
        "RunContainerError",
    }

    FAILURE_MARKERS = (
        "failed to create containerd task",
        "failed to create shim task",
        "failed to create task",
        "failed to start container",
        "oci runtime create failed",
        "error response from daemon",
    )

    EXCLUSION_MARKERS = (
        "context deadline exceeded",
        "deadline exceeded",
        "timed out",
        "timeout exceeded",
        "/var/log/pods",
        "/var/log/containers",
        "log symlink",
        "log file",
        "overlay",
        "overlayfs",
        "snapshot",
        "snapshotter",
        "rootfs",
        "structure needs cleaning",
        "read-only file system",
        "permission denied",
        "exec format error",
        "no such file or directory",
        "not found",
        "manifest unknown",
        "pull access denied",
        "seccomp",
        "apparmor",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _start_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _end_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._start_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_targets_pod(self, event: dict[str, Any], pod_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if str(involved.get("kind", "")).lower() == "pod" and (
                involved.get("name") == pod_name
            ):
                return True
        return pod_name.lower() in self._event_message(event)

    def _event_targets_container(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        message = self._event_message(event)
        container_name = container_name.lower()

        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if container_name and container_name in field_path:
                return True

        if not container_name:
            return assume_single_container

        container_patterns = (
            f'container "{container_name}"',
            f"container {container_name}",
            f"failed container {container_name}",
            f"containers{{{container_name.lower()}}}",
        )
        if any(pattern in message for pattern in container_patterns):
            return True

        return assume_single_container and "container" not in message

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(count, 1)

    def _is_runtime_failure(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        reason = self._event_reason(event)
        if reason != "failed":
            return False

        if not self._event_targets_pod(event, pod_name):
            return False
        if not self._event_targets_container(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False

        message = self._event_message(event)
        if any(marker in message for marker in self.EXCLUSION_MARKERS):
            return False

        return any(marker in message for marker in self.FAILURE_MARKERS)

    def _is_start_success(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        if self._event_reason(event) != "started":
            return False
        if not self._event_targets_pod(event, pod_name):
            return False
        return self._event_targets_container(
            event,
            container_name,
            assume_single_container=assume_single_container,
        )

    def _startup_waiting_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        statuses = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") in self.WAITING_REASONS:
                statuses.append(status)
        return statuses

    def _episode(
        self,
        episode_type: str,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        start = self._start_time(event)
        end = self._end_time(event) or start
        return {
            "type": episode_type,
            "start": start,
            "end": end,
            "count": self._occurrences(event) if episode_type == "F" else 1,
            "events": [event],
        }

    def _collapse_episodes(
        self,
        ordered_events: list[dict[str, Any]],
        *,
        pod_name: str,
        container_name: str,
        assume_single_container: bool,
    ) -> list[dict[str, Any]]:
        episodes: list[dict[str, Any]] = []

        for event in ordered_events:
            if self._is_runtime_failure(
                event,
                pod_name=pod_name,
                container_name=container_name,
                assume_single_container=assume_single_container,
            ):
                episode_type = "F"
            elif self._is_start_success(
                event,
                pod_name=pod_name,
                container_name=container_name,
                assume_single_container=assume_single_container,
            ):
                episode_type = "S"
            else:
                continue

            current = self._episode(episode_type, event)
            if episodes and episodes[-1]["type"] == episode_type:
                episodes[-1]["count"] += current["count"]
                if current["start"] is not None and (
                    episodes[-1]["start"] is None
                    or current["start"] < episodes[-1]["start"]
                ):
                    episodes[-1]["start"] = current["start"]
                if current["end"] is not None and (
                    episodes[-1]["end"] is None or current["end"] > episodes[-1]["end"]
                ):
                    episodes[-1]["end"] = current["end"]
                episodes[-1]["events"].append(event)
                continue

            episodes.append(current)

        return episodes

    def _best_candidate(
        self, pod: dict[str, Any], timeline: Timeline
    ) -> dict[str, Any] | None:
        pod_name = pod.get("metadata", {}).get("name", "")
        if not pod_name:
            return None

        waiting_statuses = self._startup_waiting_statuses(pod)
        if not waiting_statuses and pod.get("status", {}).get("phase") != "Pending":
            return None

        ordered = self._ordered_events(timeline)
        if not ordered:
            return None

        all_statuses = pod.get("status", {}).get("containerStatuses", []) or []
        candidate_names = [
            str(status.get("name", "")) for status in (waiting_statuses or all_statuses)
        ]
        if not candidate_names:
            candidate_names = [
                str(container.get("name", ""))
                for container in pod.get("spec", {}).get("containers", []) or []
            ]

        candidate_names = [name for name in candidate_names if name]
        if not candidate_names:
            return None

        assume_single_container = len(candidate_names) == 1
        best: dict[str, Any] | None = None

        for container_name in candidate_names:
            episodes = self._collapse_episodes(
                ordered,
                pod_name=pod_name,
                container_name=container_name,
                assume_single_container=assume_single_container,
            )
            if len(episodes) < 3:
                continue
            if episodes[-1]["type"] != "F":
                continue

            for idx in range(len(episodes) - 2):
                first, second, third = episodes[idx : idx + 3]
                if [first["type"], second["type"], third["type"]] != ["F", "S", "F"]:
                    continue

                if (
                    first["start"] is None
                    or second["start"] is None
                    or third["end"] is None
                ):
                    continue

                if third["end"] - first["start"] > self.MAX_PATTERN_SPAN:
                    continue

                total_failures = first["count"] + third["count"]
                if total_failures < self.MIN_FAILURE_OCCURRENCES:
                    continue

                status: dict[str, Any] = next(
                    (
                        item
                        for item in all_statuses
                        if str(item.get("name", "")) == container_name
                    ),
                    {},
                )
                restart_count = int(status.get("restartCount", 0) or 0)
                waiting = status.get("state", {}).get("waiting") or {}
                waiting_reason = str(waiting.get("reason", "") or "")

                if not waiting_statuses and restart_count < 1:
                    continue

                candidate = {
                    "container_name": container_name,
                    "first_failure": first,
                    "success": second,
                    "second_failure": third,
                    "total_failures": total_failures,
                    "restart_count": restart_count,
                    "waiting_reason": waiting_reason,
                    "waiting_message": str(waiting.get("message", "") or ""),
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (
                    best["total_failures"],
                    best["restart_count"],
                    best["second_failure"]["end"] or datetime.min,
                )
                candidate_key = (
                    candidate["total_failures"],
                    candidate["restart_count"],
                    candidate["second_failure"]["end"] or datetime.min,
                )
                if candidate_key > best_key:
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("RuntimeFailureBurst requires a Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("RuntimeFailureBurst explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        restart_count = candidate["restart_count"]
        waiting_reason = candidate["waiting_reason"] or "Pending"
        total_failures = candidate["total_failures"]
        span_minutes = (
            candidate["second_failure"]["end"] - candidate["first_failure"]["start"]
        ).total_seconds() / 60
        recovery_minutes = (
            candidate["second_failure"]["start"] - candidate["success"]["start"]
        ).total_seconds() / 60

        failure_messages = [
            str(event.get("message", ""))
            for event in (
                candidate["first_failure"]["events"]
                + candidate["second_failure"]["events"]
            )
            for _ in range(self._occurrences(event))
        ]
        dominant_message = max(set(failure_messages), key=failure_messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="RUNTIME_START_FAILURE_OBSERVED",
                    message=f"Container '{container_name}' experienced runtime startup failures in multiple recent episodes",
                    role="execution_context",
                ),
                Cause(
                    code="TRANSIENT_RUNTIME_RECOVERY_BETWEEN_FAILURES",
                    message="The container briefly reached a Started state before runtime startup failures returned",
                    role="temporal_context",
                ),
                Cause(
                    code="RUNTIME_FAILURE_BURST",
                    message="Container runtime startup instability is bursting rather than remaining a single isolated failure",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_RETURNED_TO_STARTUP_ERROR",
                    message="The pod returned to a startup failure state after transient recovery",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container runtime startup failures are bursting with brief successful starts in between",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Container '{container_name}' showed runtime startup failure -> Started -> runtime startup failure within {span_minutes:.1f} minutes",
                f"Runtime start failures accounted for {total_failures} attempt(s) across the burst",
                f"Transient recovery lasted about {recovery_minutes:.1f} minutes before failure resumed",
                f"Container is currently back in waiting startup state ({waiting_reason}) with restartCount={restart_count}",
                "Burst uses kubelet timeline ordering rather than a single failure snapshot",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod startup alternated between runtime failure and temporary success before failing again"
                ],
                f"container:{container_name}": [
                    f"Container restartCount={restart_count} and latest startup state is {waiting_reason}",
                    dominant_message,
                ],
            },
            "likely_causes": [
                "containerd or CRI-O on the node is intermittently unstable and briefly recovers between startup attempts",
                "A runtime shim or low-level OCI path is flapping, allowing some starts to succeed before failing again",
                "Node-level runtime dependencies such as cgroups, shim processes, or daemon state are unstable during container launch",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                "Inspect kubelet and containerd or CRI-O logs for alternating start success and runtime create-task failures",
                "Check runtime daemon restarts and shim stability on the node during the burst window",
            ],
        }
