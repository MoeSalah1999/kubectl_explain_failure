from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProbeConflictStartupVsLivenessRule(FailureRule):
    """
    Detects contradictory probe signals where kubelet reports liveness failures
    while the same container is still failing startup probes.

    Real-world Kubernetes semantics:
    - When startupProbe is configured, kubelet does not begin liveness checks
      until the startup probe has succeeded for that container.
    - If recent startupProbe failure events overlap with livenessProbe failure
      events for the same unresolved container, the liveness signal should not
      be treated as the primary explanation.
    - In practice this usually points to startup still being the real problem,
      while event history across restart boundaries makes the Pod look like a
      liveness failure incident.
    """

    name = "ProbeConflictStartupVsLiveness"
    category = "Compound"
    priority = 62
    deterministic = True

    blocks = [
        "StartupProbeFailure",
        "LivenessProbeFailure",
        "CrashLoopBackOff",
        "CrashLoopLivenessProbe",
        "RepeatedProbeFailureEscalation",
    ]

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 15
    MAX_SIGNAL_GAP_SECONDS = 90
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

    def _configured_probe_containers(self, pod: dict[str, Any]) -> set[str]:
        names = set()
        for container in pod.get("spec", {}).get("containers", []) or []:
            if container.get("startupProbe") and container.get("livenessProbe"):
                name = str(container.get("name", "")).strip()
                if name:
                    names.add(name)
        return names

    def _container_status(
        self,
        pod: dict[str, Any],
        container_name: str,
    ) -> dict[str, Any] | None:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if str(status.get("name", "")).strip() == container_name:
                return status
        if len(statuses) == 1:
            return statuses[0]
        return None

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

    def _is_probe_failure_event(
        self,
        event: dict[str, Any],
        *,
        probe_kind: str,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        if self._event_reason(event) not in self.FAILURE_REASONS:
            return False

        message = self._event_message(event)
        if f"{probe_kind} probe" not in message or "fail" not in message:
            return False

        return self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        )

    def _events_bounds(
        self,
        events: list[dict[str, Any]],
    ) -> tuple[datetime, datetime] | None:
        starts = [
            dt for event in events if (dt := self._event_start(event)) is not None
        ]
        ends = [dt for event in events if (dt := self._event_end(event)) is not None]
        if not starts or not ends:
            return None

        start = min(starts)
        end = max(ends)
        if end < start:
            start, end = end, start
        return start, end

    def _windows_conflict(
        self,
        startup_bounds: tuple[datetime, datetime],
        liveness_bounds: tuple[datetime, datetime],
    ) -> bool:
        startup_start, startup_end = startup_bounds
        liveness_start, liveness_end = liveness_bounds
        gap = timedelta(seconds=self.MAX_SIGNAL_GAP_SECONDS)

        return (
            startup_start <= liveness_end + gap and liveness_start <= startup_end + gap
        )

    def _status_is_unresolved(
        self, status: dict[str, Any]
    ) -> tuple[bool, int, bool, str]:
        restart_count = int(status.get("restartCount", 0) or 0)
        ready = bool(status.get("ready", False))

        current_state = status.get("state", {}) or {}
        if "waiting" in current_state:
            state_name = "waiting"
        elif "terminated" in current_state:
            state_name = "terminated"
        elif "running" in current_state:
            state_name = "running"
        else:
            state_name = "unknown"

        last_state = status.get("lastState", {}) or {}
        unstable = (
            not ready
            or restart_count > 0
            or "waiting" in current_state
            or "terminated" in current_state
            or "terminated" in last_state
        )
        return unstable, restart_count, ready, state_name

    def _dominant_message(self, events: list[dict[str, Any]]) -> str:
        messages = {str(event.get("message", "")) for event in events}
        return max(
            messages,
            key=lambda message: sum(
                self._occurrences(event)
                for event in events
                if str(event.get("message", "")) == message
            ),
        )

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        recent_events = timeline.events_within_window(self.WINDOW_MINUTES)
        if not recent_events:
            return None

        configured = self._configured_probe_containers(pod)
        if not configured:
            return None

        assume_single_container = len(configured) == 1
        best: dict[str, Any] | None = None

        for container_name in configured:
            status = self._container_status(pod, container_name)
            if status is None:
                continue

            startup_events = [
                event
                for event in recent_events
                if self._is_probe_failure_event(
                    event,
                    probe_kind="startup",
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]
            if not startup_events:
                continue

            liveness_events = [
                event
                for event in recent_events
                if self._is_probe_failure_event(
                    event,
                    probe_kind="liveness",
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]
            if not liveness_events:
                continue

            startup_bounds = self._events_bounds(startup_events)
            liveness_bounds = self._events_bounds(liveness_events)
            if startup_bounds is None or liveness_bounds is None:
                continue

            if not self._windows_conflict(startup_bounds, liveness_bounds):
                continue

            unstable, restart_count, ready, state_name = self._status_is_unresolved(
                status
            )
            if not unstable:
                continue

            startup_occurrences = sum(
                self._occurrences(event) for event in startup_events
            )
            liveness_occurrences = sum(
                self._occurrences(event) for event in liveness_events
            )

            candidate = {
                "container_name": container_name,
                "ready": ready,
                "restart_count": restart_count,
                "state_name": state_name,
                "startup_occurrences": startup_occurrences,
                "liveness_occurrences": liveness_occurrences,
                "dominant_startup_message": self._dominant_message(startup_events),
                "dominant_liveness_message": self._dominant_message(liveness_events),
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["startup_occurrences"],
                best["liveness_occurrences"],
                best["restart_count"],
            )
            candidate_key = (
                candidate["startup_occurrences"],
                candidate["liveness_occurrences"],
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
            raise ValueError(
                "ProbeConflictStartupVsLiveness requires a Timeline context"
            )

        candidate = self._candidate(pod, timeline)
        if candidate is None:
            raise ValueError(
                "ProbeConflictStartupVsLiveness explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        container_name = candidate["container_name"]
        restart_count = candidate["restart_count"]
        ready = candidate["ready"]
        state_name = candidate["state_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="STARTUP_PROBE_GATES_LIVENESS",
                    message=(
                        f"Container '{container_name}' defines startupProbe and "
                        "livenessProbe, so kubelet should gate liveness on startup success"
                    ),
                    role="healthcheck_context",
                ),
                Cause(
                    code="STARTUP_PROBE_STILL_FAILING",
                    message="Startup probe is still the active failure signal for the container",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="LIVENESS_SIGNAL_CONFLICTS_WITH_STARTUP_GATE",
                    message="Reported liveness failures overlap unresolved startup failure and are not the primary diagnosis",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "startupProbe failure is the primary issue; liveness signal conflicts "
                "with startup gating"
            ),
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Container '{container_name}' defines both startupProbe and livenessProbe",
                "Recent kubelet events show startupProbe failures overlapping liveness probe failures",
                (
                    f"Container '{container_name}' remains unstable with ready={ready}, "
                    f"state={state_name}, restartCount={restart_count}"
                ),
                "Kubernetes should not evaluate liveness probes until startupProbe succeeds",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "startupProbe failures overlap liveness failures for the same unresolved container"
                ],
                f"container:{container_name}": [
                    "Container defines both startupProbe and livenessProbe",
                    candidate["dominant_startup_message"],
                    candidate["dominant_liveness_message"],
                ],
            },
            "likely_causes": [
                "The startupProbe budget does not cover the application's real initialization time",
                "startupProbe and livenessProbe are checking the container before the application has fully initialized",
                "Rapid restarts are mixing startup and liveness events across the same pod incident",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                (
                    "Review startupProbe and livenessProbe together, especially "
                    "initialDelaySeconds, periodSeconds, and failureThreshold"
                ),
                (
                    "Confirm the startup probe only succeeds after the application and "
                    "its critical dependencies are fully initialized"
                ),
                f"kubectl logs {pod_name} -n {namespace} -c {container_name} --previous",
            ],
        }
