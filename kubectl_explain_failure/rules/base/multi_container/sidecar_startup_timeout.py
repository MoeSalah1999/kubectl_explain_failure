from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
)
from kubectl_explain_failure.timeline import Timeline


class SidecarStartupTimeoutRule(FailureRule):
    """
    Detects multi-container pods where a recognized sidecar times out during
    startup before reaching a healthy started state.

    Real-world behavior:
    - sidecars such as mesh proxies, agents, or log collectors often have their
      own runtime bootstrap path and projected dependencies
    - kubelet may emit timeout-shaped startup failures specific to that sidecar
      while the primary application is already running or still waiting on the
      pod to finish converging
    - this is more specific than a generic container start timeout because the
      degraded component is the supporting sidecar in a multi-container pod
    """

    name = "SidecarStartupTimeout"
    category = "MultiContainer"
    priority = 87
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ContainerStartTimeout",
        "ContainerRuntimeStartFailure",
    ]

    WINDOW_MINUTES = 20
    SIDECAR_WAITING_REASONS = {
        "ContainerCreating",
        "CreateContainerError",
        "RunContainerError",
    }
    PRIMARY_WAITING_REASONS = {
        "PodInitializing",
        "ContainerCreating",
    }
    TIMEOUT_MARKERS = (
        "context deadline exceeded",
        "deadline exceeded",
        "timed out",
        "timeout exceeded",
    )
    START_CONTEXT_MARKERS = (
        "failed to start container",
        "startcontainer",
        "starting container",
        "failed to create containerd task",
        "create container",
        "createcontainer",
        "containerd task",
        "shim task",
    )
    EXCLUSION_MARKERS = (
        "permission denied",
        "exec format error",
        "no such file or directory",
        "not found",
        "pull access denied",
        "manifest unknown",
        "imagepullbackoff",
        "errimagepull",
    )
    CACHE_KEY = "_sidecar_startup_timeout_candidate"

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).strip()

    def _occurrences(self, event: dict[str, Any]) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        return is_recognized_sidecar_container(pod, container_name)

    def _is_timeout_start_message(self, message: str) -> bool:
        lowered = (message or "").lower()
        if not lowered:
            return False

        if any(marker in lowered for marker in self.EXCLUSION_MARKERS):
            return False

        has_timeout = any(marker in lowered for marker in self.TIMEOUT_MARKERS)
        has_start_context = any(
            marker in lowered for marker in self.START_CONTEXT_MARKERS
        )
        return has_timeout and has_start_context

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

    def _sidecar_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if self._is_sidecar(pod, str(status.get("name", "")))
        ]

    def _primary_impact(self, pod: dict[str, Any]) -> dict[str, list[dict[str, str]]] | None:
        primaries = [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if not self._is_sidecar(pod, str(status.get("name", "")))
        ]
        if not primaries:
            return None

        ready: list[dict[str, str]] = []
        blocked: list[dict[str, str]] = []

        for status in primaries:
            name = str(status.get("name", ""))
            if not name:
                continue

            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            restart_count = int(status.get("restartCount", 0) or 0)
            waiting_reason = str(waiting.get("reason", "") or "PodInitializing")

            if state.get("running") and bool(status.get("ready")):
                ready.append({"name": name, "state": "Ready"})
                continue

            if restart_count > 0:
                return None

            if waiting and waiting_reason in self.PRIMARY_WAITING_REASONS:
                blocked.append({"name": name, "state": waiting_reason})
                continue

            return None

        if not ready and not blocked:
            return None

        return {"ready": ready, "blocked": blocked}

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        recent_events = self._recent_events(timeline)
        if not recent_events:
            return None

        primary_impact = self._primary_impact(pod)
        if primary_impact is None:
            return None

        candidates: list[dict[str, Any]] = []
        for status in self._sidecar_statuses(pod):
            sidecar_name = str(status.get("name", ""))
            if not sidecar_name or bool(status.get("ready")):
                continue

            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            waiting_reason = str(waiting.get("reason", ""))
            if waiting_reason == "CrashLoopBackOff":
                continue
            if waiting_reason not in self.SIDECAR_WAITING_REASONS:
                continue

            timeout_events = [
                event
                for event in recent_events
                if self._container_event_match(event, sidecar_name)
                and self._is_timeout_start_message(self._message(event))
            ]
            if not timeout_events:
                continue

            total_occurrences = sum(self._occurrences(event) for event in timeout_events)
            if total_occurrences < 2 and len(timeout_events) < 2:
                continue

            weighted_messages = [
                self._message(event)
                for event in timeout_events
                for _ in range(self._occurrences(event))
            ]
            dominant_message = max(set(weighted_messages), key=weighted_messages.count)

            candidates.append(
                {
                    "status": status,
                    "timeout_events": timeout_events,
                    "total_occurrences": total_occurrences,
                    "dominant_message": dominant_message,
                    "primary_impact": primary_impact,
                }
            )

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda candidate: (
                candidate["total_occurrences"],
                len(candidate["timeout_events"]),
                int(candidate["status"].get("restartCount", 0) or 0),
                str(candidate["status"].get("name", "")),
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
            raise ValueError("SidecarStartupTimeout explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sidecar = candidate["status"]
        sidecar_name = str(sidecar.get("name", "<sidecar>"))
        restart_count = int(sidecar.get("restartCount", 0) or 0)
        waiting_reason = str(
            (sidecar.get("state", {}) or {}).get("waiting", {}).get("reason", "")
        )
        primary_ready = candidate["primary_impact"]["ready"]
        primary_blocked = candidate["primary_impact"]["blocked"]
        dominant_message = str(candidate["dominant_message"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_ROLE_IDENTIFIED",
                    message=f"Container '{sidecar_name}' is acting as a sidecar alongside the primary workload",
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_START_PATH_TIMED_OUT",
                    message=f"Sidecar container '{sidecar_name}' is timing out in the runtime start path before reaching a healthy started state",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="PRIMARY_WORKLOAD_IMPACT_OBSERVED",
                    message="The pod remains degraded because the primary workload and sidecar have not converged to a healthy multi-container state",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Recognized sidecar container '{sidecar_name}' is still waiting to start with reason {waiting_reason} and ready=False",
            f"Recent kubelet/runtime failure events show startup timeout markers specific to sidecar '{sidecar_name}'",
            f"Estimated timeout signal strength is {candidate['total_occurrences']} occurrence(s) within the last {self.WINDOW_MINUTES} minutes",
            f"Dominant timeout error: {dominant_message}",
        ]
        if primary_ready:
            evidence.append(
                f"Primary container '{primary_ready[0]['name']}' is already Ready, so the sidecar timeout is the remaining degraded component"
            )
        elif primary_blocked:
            evidence.append(
                f"Primary container '{primary_blocked[0]['name']}' is still waiting: {primary_blocked[0]['state']}"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod has not reached a healthy multi-container state because the supporting sidecar is timing out during startup"
            ],
            f"container:{sidecar_name}": [
                f"state=waiting, reason={waiting_reason}, restartCount={restart_count}, ready={bool(sidecar.get('ready'))}"
            ],
        }
        if primary_ready:
            object_evidence[f"container:{primary_ready[0]['name']}"] = [
                "Primary workload container is already Ready while the sidecar remains stuck starting"
            ]
        elif primary_blocked:
            object_evidence[f"container:{primary_blocked[0]['name']}"] = [
                f"Primary workload container is still waiting with reason {primary_blocked[0]['state']}"
            ]

        return {
            "root_cause": "Recognized sidecar container timed out during startup before reaching a healthy started state",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The sidecar bootstrap path depends on mesh, agent, or projected-volume inputs that are not becoming ready in time",
                "containerd or another runtime component is hanging specifically while creating or starting the sidecar container",
                "Sidecar-specific startup hooks, iptables setup, or certificate/bootstrap initialization are exceeding kubelet deadlines",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name} --previous",
                "Check kubelet and container runtime logs for sidecar-specific start timeout or containerd task errors",
                "Inspect mesh, agent, or bootstrap configuration that must complete before the sidecar can start",
            ],
        }
