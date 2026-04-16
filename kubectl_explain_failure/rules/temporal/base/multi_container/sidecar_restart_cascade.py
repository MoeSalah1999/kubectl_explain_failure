from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
    is_restartable_init_sidecar,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class SidecarRestartCascadeRule(FailureRule):
    """
    Detects restart cascades where a recognized sidecar begins restarting and
    the main workload container then restarts shortly afterward.

    Real-world behavior:
    - proxies, agents, and other sidecars can restart independently while the
      Pod phase remains Running
    - applications sometimes stay tightly coupled to the sidecar's availability
      and begin failing liveness checks or restart shortly after the sidecar is
      disrupted
    - kubelet often coalesces repeated restart signals into single events using
      `count`, `firstTimestamp`, and `lastTimestamp`, so cascade detection must
      reason over ordered event windows rather than raw event list length alone
    """

    name = "SidecarRestartCascade"
    category = "Temporal"
    priority = 76
    deterministic = False

    phases = ["Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
        "ProbeFailureEscalation",
        "ProbeTooAggressiveCausingRestarts",
    ]

    WINDOW_MINUTES = 20
    MAX_CASCADE_GAP = timedelta(minutes=4)
    MIN_SEQUENCE_OCCURRENCES = 2
    CACHE_KEY = "_sidecar_restart_cascade_candidate"

    SIDECAR_FAILURE_MARKERS = (
        "restart",
        "restarted",
        "back-off restarting failed",
        "crashloopbackoff",
        "failed liveness probe",
        "failed startup probe",
        "failed to start container",
        "failed container",
    )

    PRIMARY_RESTART_MARKERS = (
        "restart",
        "restarted",
        "back-off restarting failed",
        "failed liveness probe",
        "failed startup probe",
    )

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

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            return max(int(raw_count), 1)
        except Exception:
            return 1

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not container_name:
            return assume_single_container

        lowered = container_name.lower()
        involved = event.get("involvedObject", {}) or {}
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path and lowered in field_path:
                return True

        message = self._event_message(event)
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"failed container {lowered}",
            f"containers{{{lowered}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True

        return assume_single_container and "container " not in message

    def _sidecar_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            container_name = str(status.get("name", ""))
            if not is_recognized_sidecar_container(pod, container_name):
                continue
            candidates.append(status)

        for status in pod.get("status", {}).get("initContainerStatuses", []) or []:
            container_name = str(status.get("name", ""))
            if not is_restartable_init_sidecar(pod, container_name):
                continue
            candidates.append(status)

        return candidates

    def _primary_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if not is_recognized_sidecar_container(pod, str(status.get("name", "")))
        ]

    def _is_sidecar_restart_signal(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_sidecar: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_sidecar,
        ):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason in {"backoff", "crashloopbackoff"}:
            return True

        if reason == "killing":
            return any(marker in message for marker in self.SIDECAR_FAILURE_MARKERS)

        if reason == "failed":
            return any(marker in message for marker in self.SIDECAR_FAILURE_MARKERS)

        return False

    def _is_primary_restart_signal(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_primary: bool,
        restart_count: int,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_primary,
        ):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason in {"backoff", "crashloopbackoff"}:
            return True

        if reason == "killing":
            return any(marker in message for marker in self.PRIMARY_RESTART_MARKERS)

        if reason == "started":
            return restart_count >= 1 and "started container" in message

        return False

    def _events_form_cascade(
        self,
        sidecar_event: dict[str, Any],
        primary_event: dict[str, Any],
    ) -> tuple[bool, float]:
        sidecar_start = self._event_start(sidecar_event)
        sidecar_end = self._event_end(sidecar_event) or sidecar_start
        primary_start = self._event_start(primary_event)

        if sidecar_start is None or sidecar_end is None or primary_start is None:
            return False, 0.0

        if primary_start < sidecar_start:
            return False, 0.0

        if primary_start <= sidecar_end:
            return True, 0.0

        gap = primary_start - sidecar_end
        if gap > self.MAX_CASCADE_GAP:
            return False, 0.0

        return True, gap.total_seconds()

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        sidecars = [
            status
            for status in self._sidecar_statuses(pod)
            if int(status.get("restartCount", 0) or 0) >= 1
        ]
        primaries = [
            status
            for status in self._primary_statuses(pod)
            if int(status.get("restartCount", 0) or 0) >= 1
        ]

        if not sidecars or not primaries:
            return None

        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        assume_single_sidecar = len(sidecars) == 1
        assume_single_primary = len(primaries) == 1
        best: dict[str, Any] | None = None

        for sidecar in sidecars:
            sidecar_name = str(sidecar.get("name", "") or "<sidecar>")
            sidecar_events = [
                event
                for event in ordered
                if self._is_sidecar_restart_signal(
                    event,
                    container_name=sidecar_name,
                    assume_single_sidecar=assume_single_sidecar,
                )
            ]
            if not sidecar_events:
                continue

            for primary in primaries:
                primary_name = str(primary.get("name", "") or "<container>")
                primary_restart_count = int(primary.get("restartCount", 0) or 0)
                primary_events = [
                    event
                    for event in ordered
                    if self._is_primary_restart_signal(
                        event,
                        container_name=primary_name,
                        assume_single_primary=assume_single_primary,
                        restart_count=primary_restart_count,
                    )
                ]
                if not primary_events:
                    continue

                sequences: list[dict[str, Any]] = []
                used_primary_indices: set[int] = set()

                for sidecar_event in sidecar_events:
                    for primary_index, primary_event in enumerate(primary_events):
                        if primary_index in used_primary_indices:
                            continue

                        forms_cascade, gap_seconds = self._events_form_cascade(
                            sidecar_event,
                            primary_event,
                        )
                        if not forms_cascade:
                            primary_start = self._event_start(primary_event)
                            sidecar_end = self._event_end(sidecar_event)
                            if (
                                primary_start is not None
                                and sidecar_end is not None
                                and primary_start > sidecar_end
                            ):
                                break
                            continue

                        sequences.append(
                            {
                                "sidecar_event": sidecar_event,
                                "primary_event": primary_event,
                                "strength": min(
                                    self._occurrences(sidecar_event),
                                    self._occurrences(primary_event),
                                ),
                                "gap_seconds": gap_seconds,
                            }
                        )
                        used_primary_indices.add(primary_index)
                        break

                total_strength = sum(seq["strength"] for seq in sequences)
                if not sequences or total_strength < self.MIN_SEQUENCE_OCCURRENCES:
                    continue

                dominant = max(
                    sequences,
                    key=lambda seq: (
                        seq["strength"],
                        self._event_start(seq["primary_event"]) or datetime.min,
                    ),
                )

                candidate = {
                    "sidecar": sidecar,
                    "primary": primary,
                    "sequences": sequences,
                    "total_strength": total_strength,
                    "representative_gap_seconds": dominant["gap_seconds"],
                    "sidecar_message": str(
                        dominant["sidecar_event"].get("message", "")
                    ).strip(),
                    "primary_message": str(
                        dominant["primary_event"].get("message", "")
                    ).strip(),
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (
                    best["total_strength"],
                    len(best["sequences"]),
                    int(best["sidecar"].get("restartCount", 0) or 0),
                    int(best["primary"].get("restartCount", 0) or 0),
                )
                candidate_key = (
                    candidate["total_strength"],
                    len(candidate["sequences"]),
                    int(candidate["sidecar"].get("restartCount", 0) or 0),
                    int(candidate["primary"].get("restartCount", 0) or 0),
                )
                if candidate_key > best_key:
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError("SidecarRestartCascade explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        sidecar_name = str(candidate["sidecar"].get("name", "<sidecar>"))
        primary_name = str(candidate["primary"].get("name", "<container>"))
        sidecar_restart_count = int(candidate["sidecar"].get("restartCount", 0) or 0)
        primary_restart_count = int(candidate["primary"].get("restartCount", 0) or 0)
        sequence_count = len(candidate["sequences"])
        total_strength = int(candidate["total_strength"])
        representative_gap_seconds = int(round(candidate["representative_gap_seconds"]))

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_ROLE_IDENTIFIED",
                    message=(
                        f"Container '{sidecar_name}' is acting as a sidecar "
                        "alongside the primary workload"
                    ),
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_RESTART_EPISODES_OBSERVED",
                    message=(
                        f"Recent kubelet events show restart pressure for sidecar "
                        f"'{sidecar_name}'"
                    ),
                    role="temporal_context",
                ),
                Cause(
                    code="SIDECAR_RESTART_CASCADES_TO_MAIN",
                    message=(
                        f"Main container '{primary_name}' restarts shortly after "
                        f"sidecar '{sidecar_name}' restart episodes"
                    ),
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STABILITY_DEGRADED_BY_RESTART_CASCADE",
                    message=(
                        "Pod stability is degraded because sidecar restart "
                        "episodes propagate into the main workload"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                "Recognized sidecar restarts are cascading into main container "
                "restarts"
            ),
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (
                    f"Recognized sidecar '{sidecar_name}' has restartCount="
                    f"{sidecar_restart_count} while primary container "
                    f"'{primary_name}' has restartCount={primary_restart_count}"
                ),
                (
                    f"Timeline shows {sequence_count} ordered sidecar-restart -> "
                    f"main-restart cascade sequence(s) within the last "
                    f"{self.WINDOW_MINUTES} minutes"
                ),
                (
                    f"Total coalesced cascade strength across matched sequences: "
                    f"{total_strength} occurrence(s)"
                ),
                (
                    "Representative cascade gap between sidecar restart signal and "
                    f"main restart was about {representative_gap_seconds}s"
                ),
                f"Representative sidecar restart signal: {candidate['sidecar_message']}",
                f"Representative main restart signal: {candidate['primary_message']}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Ordered kubelet events show sidecar restart activity preceding main-container restarts in the same incident window"
                ],
                f"container:{sidecar_name}": [
                    f"Container restartCount={sidecar_restart_count} with recent sidecar-specific restart signals",
                    candidate["sidecar_message"],
                ],
                f"container:{primary_name}": [
                    f"Container restartCount={primary_restart_count} with restart signals that follow sidecar disruption",
                    candidate["primary_message"],
                ],
            },
            "likely_causes": [
                "The main workload is tightly coupled to a proxy or agent sidecar and does not tolerate short sidecar outages",
                "Sidecar bootstrap, certificate rotation, or config reload is unstable and repeatedly disrupts the application's health path",
                "Application liveness or startup behavior fails closed when the supporting sidecar is briefly unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name} --previous",
                f"kubectl logs {pod_name} -c {primary_name} --previous",
                "Compare main-container liveness or startup failures against sidecar restart timestamps",
                "Review whether the application can degrade gracefully when the sidecar restarts instead of immediately failing health checks",
            ],
        }
