from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProbeRecoveryOscillationRule(FailureRule):
    """
    Detects probes that briefly recover and then fail again within the same
    incident window, indicating an unstable health signal rather than a single
    steady-state failure.

    Real-world behavior:
    - readiness health often oscillates when the probe is coupled to a slow or
      unstable dependency, or when probe thresholds are too sensitive for the
      application's real behavior
    - kubelet and event sources may emit explicit recovery events such as
      `Readiness probe succeeded` or `reason=Ready`, which lets us distinguish
      fail-success-fail from a continuous failure
    - this rule is more specific than a simple probe failure because it proves
      temporary recovery followed by renewed failure on the same probe stream
    """

    name = "ProbeRecoveryOscillation"
    category = "Compound"
    priority = 63
    deterministic = False

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "IntermittentNetworkFlapping",
    ]

    WINDOW_MINUTES = 20
    MAX_SEQUENCE_SPAN = timedelta(minutes=10)

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

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
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

    def _configured_probe_containers(self, pod: dict[str, Any]) -> dict[str, set[str]]:
        configured: dict[str, set[str]] = {}
        for container in pod.get("spec", {}).get("containers", []) or []:
            name = str(container.get("name", "")).strip()
            if not name:
                continue
            probe_kinds = set()
            if container.get("readinessProbe"):
                probe_kinds.add("readiness")
            if container.get("livenessProbe"):
                probe_kinds.add("liveness")
            if container.get("startupProbe"):
                probe_kinds.add("startup")
            if probe_kinds:
                configured[name] = probe_kinds
        return configured

    def _container_status(
        self, pod: dict[str, Any], container_name: str
    ) -> dict[str, Any]:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if str(status.get("name", "")).strip() == container_name:
                return status
        if len(statuses) == 1:
            return statuses[0]
        return {}

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
        if "readiness probe" in message:
            return "readiness"
        if "liveness probe" in message:
            return "liveness"
        if "startup probe" in message:
            return "startup"
        return None

    def _event_probe_transition(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        allowed_probe_kinds: set[str],
        assume_single_container: bool,
    ) -> tuple[str | None, str | None]:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None, None

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None, None

        message = self._event_message(event)
        probe_kind = self._probe_kind_from_message(message)
        if probe_kind not in allowed_probe_kinds:
            return None, None

        reason = self._event_reason(event)
        if reason in {"unhealthy", "failed"} and "fail" in message:
            return probe_kind, "F"

        success_markers = ("probe succeeded", "succeeded")
        if reason in {"ready", "healthy"} and any(
            marker in message for marker in success_markers
        ):
            return probe_kind, "S"

        return None, None

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
            probe_kind, transition = self._event_probe_transition(
                event,
                container_name=container_name,
                allowed_probe_kinds=allowed_probe_kinds,
                assume_single_container=assume_single_container,
            )
            if probe_kind is None or transition is None:
                continue

            current = {
                "type": transition,
                "probe_kind": probe_kind,
                "start": self._event_start(event),
                "end": self._event_end(event) or self._event_start(event),
                "events": [event],
            }

            if (
                episodes
                and episodes[-1]["type"] == transition
                and episodes[-1]["probe_kind"] == probe_kind
            ):
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
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        configured = self._configured_probe_containers(pod)
        if not configured:
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
            if len(episodes) < 3:
                continue

            status = self._container_status(pod, container_name)
            ready = bool(status.get("ready", False))
            restart_count = int(status.get("restartCount", 0) or 0)
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

            for idx in range(len(episodes) - 2):
                first, second, third = episodes[idx : idx + 3]
                if [first["type"], second["type"], third["type"]] != ["F", "S", "F"]:
                    continue
                if (
                    len(
                        {first["probe_kind"], second["probe_kind"], third["probe_kind"]}
                    )
                    != 1
                ):
                    continue
                if (
                    first["start"] is None
                    or second["start"] is None
                    or third["end"] is None
                ):
                    continue
                if third["end"] - first["start"] > self.MAX_SEQUENCE_SPAN:
                    continue

                probe_kind = first["probe_kind"]
                if probe_kind == "readiness" and ready:
                    continue
                if probe_kind in {"liveness", "startup"} and restart_count < 1:
                    continue

                candidate = {
                    "container_name": container_name,
                    "probe_kind": probe_kind,
                    "ready": ready,
                    "restart_count": restart_count,
                    "state_name": state_name,
                    "dominant_failure_message": str(
                        first["events"][-1].get("message", "")
                    ),
                    "dominant_success_message": str(
                        second["events"][-1].get("message", "")
                    ),
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (best["restart_count"], 1 if not best["ready"] else 0)
                candidate_key = (
                    candidate["restart_count"],
                    1 if not candidate["ready"] else 0,
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
            raise ValueError("ProbeRecoveryOscillation requires a Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("ProbeRecoveryOscillation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        probe_kind = candidate["probe_kind"]
        ready = candidate["ready"]
        restart_count = candidate["restart_count"]
        state_name = candidate["state_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="PROBE_RECOVERY_OBSERVED",
                    message=f"Container '{container_name}' briefly recovered its {probe_kind} probe before failing again",
                    role="probe_context",
                ),
                Cause(
                    code="PROBE_HEALTH_SIGNAL_OSCILLATING",
                    message=f"The {probe_kind} probe is oscillating between failure and recovery instead of reaching a stable healthy state",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_HEALTH_FLAPPING",
                    message="The workload alternates between recovery and degradation, preventing stable readiness or runtime health",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": f"{probe_kind.capitalize()} probe health is oscillating between failure and recovery",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Timeline shows {probe_kind} probe failure -> success -> failure for container '{container_name}'",
                f"Container '{container_name}' currently reports ready={ready}, state={state_name}, restartCount={restart_count}",
                "Probe recovery was temporary and the same probe failed again in the same incident window",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"{probe_kind.capitalize()} probe state is oscillating instead of converging"
                ],
                f"container:{container_name}": [
                    candidate["dominant_failure_message"],
                    candidate["dominant_success_message"],
                ],
            },
            "likely_causes": [
                "Probe thresholds or timing are too sensitive for the application's real warm-up or dependency behavior",
                "The health endpoint briefly recovers but depends on an unstable internal or upstream condition",
                "The application is alternating between partially healthy and degraded states faster than the probe policy can absorb",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name}",
                f"Review {probe_kind} probe timing and thresholds against the application's recovery behavior",
                "Correlate the brief recovery window with dependency readiness and application startup phases",
            ],
        }
