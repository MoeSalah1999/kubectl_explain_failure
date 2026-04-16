from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class SidecarTerminationBlockRule(FailureRule):
    """
    Detects pods whose shutdown is being held open by a recognized sidecar that
    does not exit after the primary workload has already stopped.

    Real-world behavior:
    - a pod's deletion can remain stuck while a proxy/agent sidecar is still
      draining, waiting on a control plane, or ignoring SIGTERM
    - the primary app container often exits promptly, but the sidecar keeps the
      pod alive past terminationGracePeriodSeconds
    - kubelet emits sidecar-specific Killing/Failed events showing grace-period
      overruns, stop timeouts, or repeated kill attempts
    """

    name = "SidecarTerminationBlock"
    category = "MultiContainer"
    priority = 74
    deterministic = True

    phases = ["Running", "Failed"]
    container_states = ["running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "TerminationGracePeriodExceeded",
        "PreStopHookFailure",
    ]

    WINDOW_MINUTES = 30
    BLOCK_MARKERS = (
        "failed to exit within",
        "did not exit within",
        "failed to stop container",
        "context deadline exceeded",
        "termination grace period",
        "prestop hook failed",
        "still running after",
        "kill container error",
    )
    CACHE_KEY = "_sidecar_termination_block_candidate"

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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).strip()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _is_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        return is_recognized_sidecar_container(pod, container_name)

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
    ) -> bool:
        lowered = container_name.lower()
        message = self._message(event).lower()
        if lowered in message:
            return True

        involved = event.get("involvedObject", {}) or {}
        field_path = str(involved.get("fieldPath", "")).lower()
        return lowered in field_path

    def _recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _pod_deletion_time(self, pod: dict[str, Any]) -> datetime | None:
        metadata = pod.get("metadata", {}) or {}
        return self._parse_timestamp(metadata.get("deletionTimestamp"))

    def _running_sidecar_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            name = str(status.get("name", ""))
            if not self._is_sidecar(pod, name):
                continue
            state = status.get("state", {}) or {}
            if not state.get("running"):
                continue
            candidates.append(status)
        return candidates

    def _primary_shutdown_state(
        self, pod: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        primaries = [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if not self._is_sidecar(pod, str(status.get("name", "")))
        ]
        if not primaries:
            return None

        terminated: list[dict[str, Any]] = []
        for status in primaries:
            state = status.get("state", {}) or {}
            if state.get("running"):
                return None

            terminated_state = state.get("terminated") or {}
            if not terminated_state:
                terminated_state = (status.get("lastState", {}) or {}).get(
                    "terminated", {}
                ) or {}

            finished_at = self._parse_timestamp(terminated_state.get("finishedAt"))
            if finished_at is None:
                return None

            terminated.append(
                {
                    "name": str(status.get("name", "")),
                    "finished_at": finished_at,
                    "reason": str(terminated_state.get("reason", "")),
                    "exit_code": terminated_state.get("exitCode"),
                }
            )

        return terminated or None

    def _termination_kill_event(
        self,
        event: dict[str, Any],
        sidecar_name: str,
    ) -> bool:
        if not self._container_event_match(event, sidecar_name):
            return False
        return str(event.get("reason", "")).lower() == "killing"

    def _termination_block_event(
        self,
        event: dict[str, Any],
        sidecar_name: str,
    ) -> bool:
        if not self._container_event_match(event, sidecar_name):
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.BLOCK_MARKERS)

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        deletion_time = self._pod_deletion_time(pod)
        recent_events = self._recent_events(timeline)
        if deletion_time is None and not recent_events:
            return None

        primary_shutdown = self._primary_shutdown_state(pod)
        if not primary_shutdown:
            return None

        candidates: list[dict[str, Any]] = []
        pod_grace = int(pod.get("spec", {}).get("terminationGracePeriodSeconds", 30))

        for sidecar in self._running_sidecar_statuses(pod):
            sidecar_name = str(sidecar.get("name", ""))
            kill_events = [
                event
                for event in recent_events
                if self._termination_kill_event(event, sidecar_name)
            ]
            block_events = [
                event
                for event in recent_events
                if self._termination_block_event(event, sidecar_name)
            ]
            if not kill_events or not block_events:
                continue

            start_candidates: list[datetime] = []
            if deletion_time is not None:
                start_candidates.append(deletion_time)
            for event in kill_events:
                event_start = self._event_start(event)
                if event_start is not None:
                    start_candidates.append(event_start)
            if not start_candidates:
                continue

            block_ends: list[datetime] = []
            for event in block_events:
                event_end = self._event_end(event)
                if event_end is not None:
                    block_ends.append(event_end)
            if not block_ends:
                continue

            termination_started_at = min(start_candidates)
            last_block_at = max(block_ends)
            if last_block_at <= termination_started_at:
                continue

            primary_finished_at = min(item["finished_at"] for item in primary_shutdown)
            if primary_finished_at > last_block_at:
                continue

            observed_delay_seconds = (
                last_block_at - termination_started_at
            ).total_seconds()
            block_occurrences = sum(self._occurrences(event) for event in block_events)
            kill_occurrences = sum(self._occurrences(event) for event in kill_events)

            if observed_delay_seconds < pod_grace and block_occurrences < 2:
                continue

            weighted_messages = [
                self._message(event)
                for event in block_events
                for _ in range(self._occurrences(event))
            ]
            representative_block = max(
                set(weighted_messages), key=weighted_messages.count
            )

            candidates.append(
                {
                    "sidecar": sidecar,
                    "primary_shutdown": primary_shutdown,
                    "termination_started_at": termination_started_at,
                    "last_block_at": last_block_at,
                    "observed_delay_seconds": observed_delay_seconds,
                    "pod_grace": pod_grace,
                    "block_occurrences": block_occurrences,
                    "kill_occurrences": kill_occurrences,
                    "representative_block": representative_block,
                }
            )

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda candidate: (
                candidate["observed_delay_seconds"],
                candidate["block_occurrences"],
                candidate["kill_occurrences"],
                str(candidate["sidecar"].get("name", "")),
            ),
        )

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
            raise ValueError("SidecarTerminationBlock explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sidecar = candidate["sidecar"]
        sidecar_name = str(sidecar.get("name", "<sidecar>"))
        sidecar_ready = bool(sidecar.get("ready"))
        restart_count = int(sidecar.get("restartCount", 0) or 0)
        primary = candidate["primary_shutdown"][0]
        primary_name = str(primary["name"])
        primary_finished_at = primary["finished_at"].isoformat()
        observed_delay_seconds = int(round(candidate["observed_delay_seconds"]))
        termination_started_at = candidate["termination_started_at"].isoformat()
        pod_grace = int(candidate["pod_grace"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_ROLE_IDENTIFIED",
                    message=f"Container '{sidecar_name}' is acting as a sidecar alongside the primary workload",
                    role="workload_context",
                ),
                Cause(
                    code="PRIMARY_WORKLOAD_ALREADY_EXITED",
                    message=f"Primary container '{primary_name}' has already terminated while pod shutdown is still in progress",
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_NOT_EXITING_DURING_TERMINATION",
                    message=f"Sidecar container '{sidecar_name}' is not exiting within the pod termination grace period",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_TERMINATION_HELD_OPEN_BY_SIDECAR",
                    message="The pod remains stuck terminating because the sidecar is the last container still holding shutdown open",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Recognized sidecar container is blocking pod termination after the primary workload already exited",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Pod deletion/termination was already in progress by {termination_started_at}",
                f"Primary container '{primary_name}' had already terminated at {primary_finished_at}",
                f"Recognized sidecar '{sidecar_name}' is still running with ready={sidecar_ready} restartCount={restart_count} while the pod remains alive",
                f"Sidecar-specific termination block signals persisted for about {observed_delay_seconds}s, exceeding terminationGracePeriodSeconds={pod_grace}",
                f"Representative sidecar termination-block event: {candidate['representative_block']}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod termination remains open because a recognized sidecar has not exited after the primary workload stopped"
                ],
                f"container:{sidecar_name}": [
                    f"state=running, ready={sidecar_ready}, restartCount={restart_count}"
                ],
                f"container:{primary_name}": [
                    f"Primary workload container already terminated at {primary_finished_at}"
                ],
            },
            "likely_causes": [
                "The sidecar is draining or waiting on control-plane/network shutdown longer than the pod grace period allows",
                "A sidecar PreStop/drain hook or signal handler is hanging and preventing the process from exiting promptly",
                "The sidecar ignores SIGTERM or is stuck in runtime teardown, so kubelet keeps retrying shutdown past the normal deadline",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name}",
                "Inspect sidecar drain, PreStop, and terminationGracePeriodSeconds settings for shutdown paths that outlast pod deletion",
                "Check kubelet/runtime logs for repeated kill attempts or stop timeouts specific to the sidecar container",
            ],
        }
