from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
)
from kubectl_explain_failure.timeline import Timeline


class SidecarCrashLoopRule(FailureRule):
    """
    Detects multi-container pods where a recognized sidecar is the container
    actively crashlooping while the primary application container remains healthy.
    """

    name = "SidecarCrashLoop"
    category = "MultiContainer"
    priority = 68
    deterministic = True
    phases = ["Pending", "Running", "CrashLoopBackOff"]
    container_states = ["waiting", "running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 20
    BACKOFF_REASONS = {"BackOff", "CrashLoopBackOff"}
    CACHE_KEY = "_sidecar_crashloop_candidate"

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _is_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        return is_recognized_sidecar_container(pod, container_name)

    def _backoff_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")) in self.BACKOFF_REASONS
        ]

    def _container_event_match(
        self, event: dict[str, Any], container_name: str
    ) -> bool:
        lowered = container_name.lower()
        message = self._message(event)
        if lowered in message:
            return True

        involved = event.get("involvedObject", {}) or {}
        field_path = str(involved.get("fieldPath", "")).lower()
        return lowered in field_path

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        if len(statuses) < 2:
            return None

        crashlooping_sidecars: list[dict[str, Any]] = []
        healthy_primary: list[dict[str, Any]] = []
        other_primary_crashloop = False

        for status in statuses:
            name = str(status.get("name", ""))
            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            is_crashloop = waiting.get("reason") == "CrashLoopBackOff"
            is_ready = bool(status.get("ready"))
            is_sidecar = self._is_sidecar(pod, name)

            if (
                is_sidecar
                and is_crashloop
                and int(status.get("restartCount", 0) or 0) >= 1
            ):
                crashlooping_sidecars.append(status)
            elif not is_sidecar and is_ready:
                healthy_primary.append(status)
            elif not is_sidecar and is_crashloop:
                other_primary_crashloop = True

        if not crashlooping_sidecars or not healthy_primary or other_primary_crashloop:
            return None

        backoff_events = self._backoff_events(timeline)
        if not backoff_events:
            return None

        sidecar_names = [
            str(status.get("name", "")) for status in crashlooping_sidecars
        ]
        mentioned_container_names = [
            str(status.get("name", ""))
            for status in statuses
            if any(
                self._container_event_match(event, str(status.get("name", "")))
                for event in backoff_events
            )
        ]

        relevant_events = [
            event
            for event in backoff_events
            if any(self._container_event_match(event, name) for name in sidecar_names)
        ]

        if mentioned_container_names and not relevant_events:
            return None
        if not relevant_events and len(crashlooping_sidecars) == 1:
            relevant_events = backoff_events
        if not relevant_events:
            return None

        sidecar = max(
            crashlooping_sidecars,
            key=lambda status: int(status.get("restartCount", 0) or 0),
        )
        primary = max(
            healthy_primary,
            key=lambda status: int(status.get("restartCount", 0) or 0),
        )

        return {
            "sidecar": sidecar,
            "primary": primary,
            "relevant_events": relevant_events,
        }

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
            raise ValueError("SidecarCrashLoop explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sidecar_name = str(candidate["sidecar"].get("name", "<sidecar>"))
        primary_name = str(candidate["primary"].get("name", "<container>"))
        restart_count = int(candidate["sidecar"].get("restartCount", 0) or 0)
        latest_event = candidate["relevant_events"][-1]
        latest_message = str(latest_event.get("message", "")).strip()

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_ROLE_IDENTIFIED",
                    message=f"Container '{sidecar_name}' is acting as a sidecar alongside the main workload",
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_CRASH_LOOP",
                    message=f"Sidecar container '{sidecar_name}' is repeatedly crashing",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="PRIMARY_CONTAINER_STILL_HEALTHY",
                    message=f"Primary container '{primary_name}' remains healthy while the sidecar fails",
                    role="container_health_context",
                ),
                Cause(
                    code="POD_DEGRADED_BY_SIDECAR_FAILURE",
                    message="Pod remains degraded because the supporting sidecar cannot stay up",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Sidecar container is crashing while the primary workload remains healthy",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Recognized sidecar container '{sidecar_name}' is waiting in CrashLoopBackOff with restartCount={restart_count}",
                f"Primary container '{primary_name}' remains Ready",
                f"Recent BackOff events are specific to sidecar container '{sidecar_name}'",
                f"Latest sidecar crash message: {latest_message}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod has a healthy primary container but a crashlooping sidecar"
                ],
                f"container:{sidecar_name}": [
                    "Recognized sidecar is in CrashLoopBackOff"
                ],
                f"container:{primary_name}": [
                    "Primary workload container remains Ready"
                ],
            },
            "likely_causes": [
                "The sidecar has invalid bootstrap or control-plane configuration",
                "The sidecar cannot reach its upstream dependency or control plane and exits during startup",
                "Injected sidecar certificates, tokens, or mesh-specific configuration are stale or missing",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name}",
                f"kubectl logs {pod_name} -c {primary_name}",
                "Inspect service-mesh, logging-agent, or proxy bootstrap configuration for the sidecar",
            ],
        }
