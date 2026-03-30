from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class LivenessProbeFailureRule(FailureRule):
    """
    Detects kubelet restarts driven by failed liveness probes.

    Real-world behavior:
    - kubelet emits `Unhealthy` events that explicitly mention `Liveness probe failed`
    - this is often followed by a `Killing` event such as
      `Container X failed liveness probe, will be restarted`
    - the Pod commonly stays in phase Running while the affected container's
      restartCount rises and lastState shows recent termination
    - this rule captures the simple, current liveness failure case before it
      becomes a larger crashloop or sustained probe-escalation incident
    """

    name = "LivenessProbeFailure"
    category = "Container"
    priority = 21
    deterministic = True

    phases = ["Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 15

    EXCLUSION_MARKERS = (
        "readiness probe",
        "startup probe",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
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
        return max(1, count)

    def _configured_liveness_containers(self, pod: dict[str, Any]) -> set[str]:
        names = set()
        for container in pod.get("spec", {}).get("containers", []) or []:
            if container.get("livenessProbe"):
                name = str(container.get("name", "")).strip()
                if name:
                    names.add(name)
        return names

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

    def _is_liveness_failure_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        message = self._event_message(event)
        if any(marker in message for marker in self.EXCLUSION_MARKERS):
            return False
        if "liveness probe" not in message or "fail" not in message:
            return False
        if self._event_reason(event) not in {"unhealthy", "failed"}:
            return False

        return self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        )

    def _is_liveness_restart_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        if self._event_reason(event) != "killing":
            return False

        message = self._event_message(event)
        if "liveness probe" not in message:
            return False
        if "restart" not in message and "restarted" not in message:
            return False

        return self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        )

    def _has_backoff(self, ordered: list[dict[str, Any]]) -> bool:
        return any(self._event_reason(event) == "backoff" for event in ordered)

    def _candidate(
        self, pod: dict[str, Any], timeline: Timeline
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        if self._has_backoff(ordered):
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        configured = self._configured_liveness_containers(pod)

        candidates = []
        for status in statuses:
            name = str(status.get("name", "") or "")
            if configured and name not in configured:
                continue
            candidates.append(status)

        if not candidates and len(statuses) == 1:
            candidates = statuses

        if not candidates:
            return None

        assume_single_container = len(candidates) == 1
        best: dict[str, Any] | None = None

        for status in candidates:
            container_name = str(status.get("name", "") or "<unknown>")
            failure_events = [
                event
                for event in ordered
                if self._is_liveness_failure_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]
            if not failure_events:
                continue

            restart_events = [
                event
                for event in ordered
                if self._is_liveness_restart_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]

            restart_count = int(status.get("restartCount", 0) or 0)
            last_terminated = (status.get("lastState", {}) or {}).get(
                "terminated"
            ) or {}
            if restart_count < 1 and not restart_events and not last_terminated:
                continue

            current_state = status.get("state", {}) or {}
            if not any(key in current_state for key in ("running", "waiting")):
                continue

            failure_occurrences = sum(
                self._occurrences(event) for event in failure_events
            )
            restart_signals = sum(self._occurrences(event) for event in restart_events)

            candidate = {
                "container_name": container_name,
                "failure_occurrences": failure_occurrences,
                "restart_signals": restart_signals,
                "restart_count": restart_count,
                "current_state": "running" if "running" in current_state else "waiting",
                "dominant_failure_message": max(
                    set(str(event.get("message", "")) for event in failure_events),
                    key=lambda msg: sum(
                        self._occurrences(event)
                        for event in failure_events
                        if str(event.get("message", "")) == msg
                    ),
                ),
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["failure_occurrences"],
                best["restart_signals"],
                best["restart_count"],
            )
            candidate_key = (
                candidate["failure_occurrences"],
                candidate["restart_signals"],
                candidate["restart_count"],
            )
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("LivenessProbeFailure requires a Timeline context")

        candidate = self._candidate(pod, timeline)
        if candidate is None:
            raise ValueError("LivenessProbeFailure explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        failure_occurrences = candidate["failure_occurrences"]
        restart_signals = candidate["restart_signals"]
        restart_count = candidate["restart_count"]
        current_state = candidate["current_state"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIVENESS_PROBE_CONFIGURED",
                    message=f"Container '{container_name}' has a liveness probe configured and recently evaluated by kubelet",
                    role="healthcheck_context",
                ),
                Cause(
                    code="LIVENESS_PROBE_FAILED",
                    message="Kubelet liveness checks are failing and triggering restarts",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_RESTARTED_BY_KUBELET",
                    message="Kubelet restarted the container after failed liveness checks",
                    role="execution_intermediate",
                ),
                Cause(
                    code="WORKLOAD_HEALTH_UNSTABLE",
                    message="The workload remains unstable because the container cannot stay healthy long enough to avoid restart pressure",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Recent kubelet events show liveness probe failure for container '{container_name}'",
            f"Liveness probe failure was observed {failure_occurrences} time(s) within the last {self.WINDOW_MINUTES} minutes",
            f"Container '{container_name}' has restartCount={restart_count} while Pod phase remains Running",
            f"Container is currently in {current_state} state after liveness-triggered restart pressure",
        ]
        if restart_signals:
            evidence.append(
                f"Kubelet emitted {restart_signals} liveness-driven restart signal(s) for the container"
            )

        return {
            "rule": self.name,
            "root_cause": "Container failing livenessProbe checks",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod stays Running but kubelet is restarting a container due to failed liveness checks"
                ],
                f"container:{container_name}": [
                    f"Container restartCount={restart_count} with recent liveness probe failures",
                    candidate["dominant_failure_message"],
                ],
            },
            "likely_causes": [
                "The liveness probe path, command, or port does not match the application's real health behavior",
                "The application becomes unhealthy after startup and fails kubelet liveness checks",
                "Probe timeoutSeconds or failureThreshold is too strict for the container's runtime behavior",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                "Review livenessProbe path, port, command, timeoutSeconds, and failureThreshold",
                "Compare kubelet probe failures with application logs and dependency availability",
            ],
        }
