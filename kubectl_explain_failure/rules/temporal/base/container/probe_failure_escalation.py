from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProbeFailureEscalationRule(FailureRule):
    """
    Detects restart-driving probe failures that have escalated into a repeated
    kubelet remediation loop.

    Real-world behavior:
    - livenessProbe and startupProbe failures can trigger kubelet restarts,
      while readinessProbe failures do not restart the container
    - Kubernetes often coalesces repeated Unhealthy/Killing events using
      `count`, `firstTimestamp`, and `lastTimestamp`, so escalation must reason
      over event episodes rather than raw list length alone
    - this rule captures the temporal pattern where the same restart-driving
      probe fails, kubelet restarts the container, and the pattern repeats
      within the same incident window
    """

    name = "ProbeFailureEscalation"
    category = "Temporal"
    priority = 56
    deterministic = False

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "CrashLoopBackOff",
        "ProbeTooAggressiveCausingRestarts",
    ]

    WINDOW_MINUTES = 20
    MAX_PATTERN_SPAN = timedelta(minutes=10)
    MAX_RESTART_GAP = timedelta(minutes=3)
    MIN_FAILURE_EPISODES = 2
    MIN_RESTART_EPISODES = 2
    FAILURE_REASONS = {"unhealthy", "failed"}

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_start(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_start(event)
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

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(count, 1)

    def _configured_restart_probe_containers(
        self, pod: dict[str, Any]
    ) -> dict[str, set[str]]:
        configured: dict[str, set[str]] = {}
        for container in pod.get("spec", {}).get("containers", []) or []:
            probe_kinds = set()
            if container.get("livenessProbe"):
                probe_kinds.add("liveness")
            if container.get("startupProbe"):
                probe_kinds.add("startup")
            if probe_kinds:
                name = str(container.get("name", "")).strip()
                if name:
                    configured[name] = probe_kinds
        return configured

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not container_name:
            return assume_single_container

        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if container_name.lower() in field_path:
                return True

        message = self._event_message(event)
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"failed container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True

        return assume_single_container and "container " not in message

    def _probe_kind_from_message(self, message: str) -> str | None:
        if "liveness probe" in message:
            return "liveness"
        if "startup probe" in message:
            return "startup"
        return None

    def _failure_event_probe_kind(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        allowed_probe_kinds: set[str],
        assume_single_container: bool,
    ) -> str | None:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None

        if self._event_reason(event) not in self.FAILURE_REASONS:
            return None

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None

        message = self._event_message(event)
        if "readiness probe" in message:
            return None
        if "fail" not in message:
            return None

        probe_kind = self._probe_kind_from_message(message)
        if probe_kind not in allowed_probe_kinds:
            return None

        return probe_kind

    def _restart_event_probe_kind(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        allowed_probe_kinds: set[str],
        assume_single_container: bool,
    ) -> str | None:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None

        if self._event_reason(event) != "killing":
            return None

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None

        message = self._event_message(event)
        if "restart" not in message and "restarted" not in message:
            return None

        probe_kind = self._probe_kind_from_message(message)
        if probe_kind not in allowed_probe_kinds:
            return None

        return probe_kind

    def _episode(
        self,
        episode_type: str,
        event: dict[str, Any],
        *,
        probe_kind: str,
    ) -> dict[str, Any]:
        start = self._event_start(event)
        end = self._event_end(event) or start
        return {
            "type": episode_type,
            "probe_kind": probe_kind,
            "start": start,
            "end": end,
            "count": self._occurrences(event),
            "events": [event],
        }

    def _collapse_episodes(
        self,
        ordered_events: list[dict[str, Any]],
        *,
        container_name: str,
        allowed_probe_kinds: set[str],
        assume_single_container: bool,
    ) -> list[dict[str, Any]]:
        episodes: list[dict[str, Any]] = []

        for event in ordered_events:
            failure_probe_kind = self._failure_event_probe_kind(
                event,
                container_name=container_name,
                allowed_probe_kinds=allowed_probe_kinds,
                assume_single_container=assume_single_container,
            )
            if failure_probe_kind is not None:
                episode_type = "F"
                probe_kind = failure_probe_kind
            else:
                restart_probe_kind = self._restart_event_probe_kind(
                    event,
                    container_name=container_name,
                    allowed_probe_kinds=allowed_probe_kinds,
                    assume_single_container=assume_single_container,
                )
                if restart_probe_kind is None:
                    continue
                episode_type = "R"
                probe_kind = restart_probe_kind

            current = self._episode(
                episode_type,
                event,
                probe_kind=probe_kind,
            )
            if (
                episodes
                and episodes[-1]["type"] == episode_type
                and episodes[-1]["probe_kind"] == probe_kind
            ):
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

    def _restarting_status(
        self,
        pod: dict[str, Any],
        container_name: str,
    ) -> dict[str, Any]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if str(status.get("name", "")) == container_name:
                return status
        return {}

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        configured = self._configured_restart_probe_containers(pod)
        if not configured:
            return None

        ordered = self._ordered_events(timeline)
        if not ordered:
            return None

        assume_single_container = len(configured) == 1
        best: dict[str, Any] | None = None

        for container_name, probe_kinds in configured.items():
            episodes = self._collapse_episodes(
                ordered,
                container_name=container_name,
                allowed_probe_kinds=probe_kinds,
                assume_single_container=assume_single_container,
            )
            if len(episodes) < 4:
                continue

            status = self._restarting_status(pod, container_name)
            restart_count = int(status.get("restartCount", 0) or 0)
            if restart_count < 2:
                continue

            current_state = status.get("state", {}) or {}
            state_name = (
                "waiting"
                if "waiting" in current_state
                else (
                    "terminated"
                    if "terminated" in current_state
                    else "running" if "running" in current_state else "unknown"
                )
            )
            ready = bool(status.get("ready", False))

            for idx in range(len(episodes) - 3):
                first, second, third, fourth = episodes[idx : idx + 4]
                if [first["type"], second["type"], third["type"], fourth["type"]] != [
                    "F",
                    "R",
                    "F",
                    "R",
                ]:
                    continue

                if (
                    len(
                        {
                            first["probe_kind"],
                            second["probe_kind"],
                            third["probe_kind"],
                            fourth["probe_kind"],
                        }
                    )
                    != 1
                ):
                    continue

                if (
                    first["start"] is None
                    or second["start"] is None
                    or third["start"] is None
                    or fourth["end"] is None
                ):
                    continue

                if second["start"] - first["end"] > self.MAX_RESTART_GAP:
                    continue
                if fourth["start"] - third["end"] > self.MAX_RESTART_GAP:
                    continue
                if fourth["end"] - first["start"] > self.MAX_PATTERN_SPAN:
                    continue

                failure_episodes = [first, third]
                restart_episodes = [second, fourth]
                total_failures = sum(item["count"] for item in failure_episodes)
                total_restarts = sum(item["count"] for item in restart_episodes)
                if total_failures < self.MIN_FAILURE_EPISODES:
                    continue
                if total_restarts < self.MIN_RESTART_EPISODES:
                    continue

                dominant_failure_message = max(
                    {
                        str(event.get("message", ""))
                        for item in failure_episodes
                        for event in item["events"]
                    },
                    key=lambda message: sum(
                        self._occurrences(event)
                        for item in failure_episodes
                        for event in item["events"]
                        if str(event.get("message", "")) == message
                    ),
                )
                dominant_restart_message = max(
                    {
                        str(event.get("message", ""))
                        for item in restart_episodes
                        for event in item["events"]
                    },
                    key=lambda message: sum(
                        self._occurrences(event)
                        for item in restart_episodes
                        for event in item["events"]
                        if str(event.get("message", "")) == message
                    ),
                )

                candidate = {
                    "container_name": container_name,
                    "probe_kind": first["probe_kind"],
                    "restart_count": restart_count,
                    "ready": ready,
                    "state_name": state_name,
                    "first_failure": first,
                    "first_restart": second,
                    "second_failure": third,
                    "second_restart": fourth,
                    "total_failures": total_failures,
                    "total_restarts": total_restarts,
                    "dominant_failure_message": dominant_failure_message,
                    "dominant_restart_message": dominant_restart_message,
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (
                    best["total_failures"],
                    best["total_restarts"],
                    best["restart_count"],
                )
                candidate_key = (
                    candidate["total_failures"],
                    candidate["total_restarts"],
                    candidate["restart_count"],
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
            raise ValueError("ProbeFailureEscalation requires a Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("ProbeFailureEscalation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        probe_kind = candidate["probe_kind"]
        restart_count = candidate["restart_count"]
        ready = candidate["ready"]
        state_name = candidate["state_name"]
        total_failures = candidate["total_failures"]
        total_restarts = candidate["total_restarts"]
        span_minutes = (
            candidate["second_restart"]["end"] - candidate["first_failure"]["start"]
        ).total_seconds() / 60

        chain = CausalChain(
            causes=[
                Cause(
                    code="RESTART_DRIVING_PROBE_FAILURES_OBSERVED",
                    message=(
                        f"Container '{container_name}' is repeatedly failing its "
                        f"{probe_kind} probe and kubelet is reacting with restarts"
                    ),
                    role="container_health_context",
                ),
                Cause(
                    code="PROBE_FAILURE_RESTART_LOOP_ESCALATING",
                    message=(
                        f"The {probe_kind} probe failure pattern has escalated into a "
                        "repeat restart loop rather than a one-off health check miss"
                    ),
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_STABILITY_DEGRADED_BY_PROBE_RESTARTS",
                    message="Repeated kubelet probe restarts are degrading workload stability",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                f"Repeated {probe_kind} probe failures escalated into a kubelet restart loop"
            ),
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (
                    f"Timeline shows {probe_kind} probe failure -> restart -> "
                    f"{probe_kind} probe failure -> restart for container '{container_name}'"
                ),
                (
                    f"Repeated probe/restart loop completed within {span_minutes:.1f} minutes "
                    f"with {total_failures} probe-failure occurrence(s) and {total_restarts} restart signal(s)"
                ),
                (
                    f"Container '{container_name}' now has restartCount={restart_count}, "
                    f"ready={ready}, state={state_name}"
                ),
                "Escalation is based on ordered kubelet probe and restart episodes, not a single failed probe event",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"{probe_kind.capitalize()} probe failures repeatedly triggered kubelet restarts in the same incident window"
                ],
                f"container:{container_name}": [
                    f"Container restartCount={restart_count} after repeated {probe_kind} probe restart cycles",
                    candidate["dominant_failure_message"],
                    candidate["dominant_restart_message"],
                ],
            },
            "likely_causes": [
                f"The {probe_kind} probe target does not reflect the application's real healthy state",
                "The application briefly recovers after restart but re-enters the same unhealthy condition",
                "Dependencies, warm-up time, or runtime load are causing the same probe-driven restart cycle to repeat",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                f"Review the {probe_kind} probe path, command, thresholds, and timing against real application behavior",
                "Correlate restart timestamps with application logs and dependency readiness to explain why the same probe failure keeps recurring",
            ],
        }
