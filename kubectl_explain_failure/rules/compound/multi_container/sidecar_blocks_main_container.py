from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_restartable_init_sidecar,
)
from kubectl_explain_failure.timeline import Timeline


class SidecarBlocksMainContainerRule(FailureRule):
    """
    Detects native sidecar init containers that block main container startup.

    Real Kubernetes behavior:
    - restartable init containers (`restartPolicy: Always`) act as native sidecars
    - kubelet does not advance to normal containers until those sidecars are
      considered started
    - if the sidecar remains `started=false` because it is crashlooping or
      failing startup checks, the main containers remain stuck in
      PodInitializing / ContainerCreating
    """

    name = "SidecarBlocksMainContainer"
    category = "Compound"
    priority = 78
    deterministic = True
    phases = ["Pending", "Running", "Init"]
    container_states = ["waiting", "running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    blocks = [
        "InitContainerBlocksMain",
        "InitContainerFailure",
        "StartupProbeFailure",
    ]

    WINDOW_MINUTES = 20
    MAIN_WAITING_REASONS = {"PodInitializing", "ContainerCreating"}
    SIDECAR_WAITING_REASONS = {
        "CrashLoopBackOff",
        "CreateContainerConfigError",
        "ImagePullBackOff",
        "ErrImagePull",
        "RunContainerError",
        "StartError",
    }
    CACHE_KEY = "_sidecar_blocks_main_container_candidate"

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).strip()

    def _event_mentions_container(
        self,
        event: dict[str, Any],
        container_name: str,
    ) -> bool:
        lowered_name = container_name.lower()
        lowered_message = self._message(event).lower()
        if lowered_name in lowered_message:
            return True

        involved = event.get("involvedObject", {}) or {}
        field_path = str(involved.get("fieldPath", "")).lower()
        return lowered_name in field_path

    def _recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _is_startup_probe_failure_event(self, event: dict[str, Any]) -> bool:
        message = self._message(event).lower()
        return "startup probe" in message and "fail" in message

    def _is_backoff_event(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason", "")).lower()
        message = self._message(event).lower()
        return reason in {"backoff", "crashloopbackoff"} or (
            "back-off restarting failed" in message
        )

    def _blocked_main_containers(
        self, pod: dict[str, Any]
    ) -> list[dict[str, str]] | None:
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        if not spec_containers:
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        statuses_by_name = {
            str(status.get("name", "")): status
            for status in statuses
            if status.get("name")
        }

        blocked: list[dict[str, str]] = []
        for container in spec_containers:
            name = str(container.get("name", ""))
            if not name:
                continue

            status = statuses_by_name.get(name, {})
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}

            if state.get("running") or state.get("terminated"):
                return None

            if int(status.get("restartCount", 0) or 0) > 0:
                return None

            waiting_reason = str(waiting.get("reason", "") or "PodInitializing")
            if waiting_reason not in self.MAIN_WAITING_REASONS:
                return None

            blocked.append({"name": name, "reason": waiting_reason})

        return blocked or None

    def _sidecar_candidates(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        recent_events = self._recent_events(timeline)
        if not recent_events:
            return []

        candidates: list[dict[str, Any]] = []
        init_statuses = pod.get("status", {}).get("initContainerStatuses", []) or []
        for status in init_statuses:
            container_name = str(status.get("name", ""))
            if not is_restartable_init_sidecar(pod, container_name):
                continue

            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            running = state.get("running", {}) or {}
            waiting_reason = str(waiting.get("reason", ""))
            started = status.get("started")
            restart_count = int(status.get("restartCount", 0) or 0)

            startup_events = [
                event
                for event in recent_events
                if self._event_mentions_container(event, container_name)
                and self._is_startup_probe_failure_event(event)
            ]
            backoff_events = [
                event
                for event in recent_events
                if self._event_mentions_container(event, container_name)
                and self._is_backoff_event(event)
            ]

            if started is True:
                continue

            if (
                not startup_events
                and not backoff_events
                and waiting_reason not in self.SIDECAR_WAITING_REASONS
            ):
                continue

            if not startup_events and not backoff_events:
                continue

            dominant_events = startup_events or backoff_events
            candidates.append(
                {
                    "status": status,
                    "container_name": container_name,
                    "started": bool(started),
                    "restart_count": restart_count,
                    "state_name": (
                        "running" if running else "waiting" if waiting else "unknown"
                    ),
                    "reason": waiting_reason
                    or str(
                        (status.get("lastState", {}) or {})
                        .get("terminated", {})
                        .get("reason", "")
                    ),
                    "startup_events": startup_events,
                    "backoff_events": backoff_events,
                    "dominant_events": dominant_events,
                    "dominant_message": self._message(dominant_events[-1]),
                }
            )

        return candidates

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        blocked_main = self._blocked_main_containers(pod)
        if not blocked_main:
            return None

        candidates = self._sidecar_candidates(pod, timeline)
        if not candidates:
            return None

        best = max(
            candidates,
            key=lambda candidate: (
                len(candidate["startup_events"]),
                len(candidate["backoff_events"]),
                candidate["restart_count"],
                candidate["container_name"],
            ),
        )

        return {
            "sidecar": best,
            "blocked_main": blocked_main,
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
            raise ValueError(
                "SidecarBlocksMainContainer explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sidecar = candidate["sidecar"]
        blocked_main = candidate["blocked_main"]
        sidecar_name = str(sidecar["container_name"])
        main_name = str(blocked_main[0]["name"])
        main_reason = str(blocked_main[0]["reason"])
        dominant_message = str(sidecar["dominant_message"])
        restart_count = int(sidecar["restart_count"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="RESTARTABLE_SIDECAR_INIT_PRESENT",
                    message=f"Pod defines restartable init sidecar '{sidecar_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_INIT_NOT_STARTED",
                    message=f"Restartable init sidecar '{sidecar_name}' has not reached a started state",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_INIT_SEQUENCE_GATED",
                    message="Kubelet will not start normal containers until restartable init sidecars are started",
                    role="platform_semantics",
                ),
                Cause(
                    code="MAIN_CONTAINER_STARTUP_BLOCKED_BY_SIDECAR",
                    message=f"Main container '{main_name}' is still blocked behind sidecar startup",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Restartable sidecar init container is blocking main container startup",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Restartable init sidecar '{sidecar_name}' is still marked started=false",
                f"Main container '{main_name}' has not started and remains waiting: {main_reason}",
                f"Recent startup-blocking events are specific to restartable init sidecar '{sidecar_name}'",
                dominant_message,
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is stuck before normal containers because a restartable init sidecar has not started"
                ],
                f"container:{sidecar_name}": [
                    f"state={sidecar['state_name']}, reason={sidecar['reason']}, restartCount={restart_count}, started={sidecar['started']}"
                ],
                f"container:{main_name}": [
                    f"Main container is still waiting with reason {main_reason}"
                ],
            },
            "likely_causes": [
                "The sidecar startupProbe is too strict or targets an endpoint that is not ready yet",
                "The sidecar cannot finish bootstrap because its mesh, agent, or control-plane dependency is unavailable",
                "The restartable init sidecar configuration is invalid and kubelet keeps retrying it before normal containers can start",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name} --previous",
                "Review the initContainers entry for restartPolicy: Always and any startupProbe gating on the sidecar",
                "Inspect service-mesh or agent bootstrap dependencies required before the sidecar can report started",
            ],
        }
