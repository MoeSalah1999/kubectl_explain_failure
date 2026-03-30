from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class RuntimeRestartBreaksPodRule(FailureRule):
    """
    Detects a pod that becomes unhealthy after the node container runtime
    briefly goes down and then recovers.

    Real-world interpretation:
    - kubelet/node events first show a CRI outage or PLEG/runtime unhealthy
      window on the assigned node
    - the node later recovers to Ready, indicating the runtime returned
    - after recovery, kubelet reports pod sandbox disruption or restart-loop
      symptoms for the same pod
    - this captures transient runtime restart fallout, not a still-ongoing
      runtime outage
    """

    name = "RuntimeRestartBreaksPod"
    category = "Compound"
    priority = 66
    deterministic = True

    blocks = [
        "ContainerRuntimeUnavailable",
        "NodeNotReady",
        "ContainerRuntimeStartFailure",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    supported_phases = {"Pending", "Running", "Unknown", "CrashLoopBackOff"}

    RUNTIME_OUTAGE_MARKERS = (
        "container runtime is down",
        "container runtime is not running",
        "container runtime status check may not have completed yet",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "runtime service failed",
        "connection refused",
        "containerd.sock",
        "cri-o.sock",
        "rpc error: code = unavailable",
        "pleg is not healthy",
    )

    VERSION_MISMATCH_MARKERS = (
        "unknown service runtime.v1.runtimeservice",
        "unknown service runtime.v1alpha2.runtimeservice",
        "runtime api version is not supported",
        "unsupported runtime api version",
        "cri v1 runtime api is not implemented",
        "unsupported service runtime.v1",
        "unsupported service runtime.v1alpha2",
    )

    NETWORK_EXCLUSION_MARKERS = (
        "network plugin not ready",
        "cni config uninitialized",
        "networkunavailable",
        "network is unavailable",
    )

    BREAK_EVENT_MARKERS = (
        "pod sandbox changed",
        "will be killed and re-created",
        "failed to create pod sandbox",
        "failed to start container",
        "failed to create containerd task",
    )

    WAITING_REASONS = {
        "CrashLoopBackOff",
        "CreateContainerError",
        "RunContainerError",
        "ContainerCreating",
    }

    def _extract_timestamp(self, event: dict[str, Any]) -> datetime | None:
        raw = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        enumerated = list(enumerate(timeline.raw_events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._extract_timestamp(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _candidate_node(
        self, pod: dict[str, Any], node_objs: dict[str, dict[str, Any]]
    ) -> tuple[str, dict[str, Any]] | None:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return assigned_node, node_objs[assigned_node]
        if len(node_objs) == 1:
            return next(iter(node_objs.items()))
        return None

    def _ready_condition(self, node: dict[str, Any]) -> dict[str, Any] | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "Ready":
                return cond
        return None

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_targets_node(self, event: dict[str, Any], node_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if str(involved.get("kind", "")).lower() == "node" and (
                involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True

        return node_name.lower() in self._event_message(event)

    def _event_targets_pod(self, event: dict[str, Any], pod_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if str(involved.get("kind", "")).lower() == "pod" and (
                involved.get("name") == pod_name
            ):
                return True

        return pod_name.lower() in self._event_message(event)

    def _has_exclusion_markers(self, text: str) -> bool:
        lowered = text.lower()
        return any(
            marker in lowered for marker in self.VERSION_MISMATCH_MARKERS
        ) or any(marker in lowered for marker in self.NETWORK_EXCLUSION_MARKERS)

    def _is_runtime_outage_precursor(
        self,
        event: dict[str, Any],
        node_name: str,
    ) -> bool:
        if not self._event_targets_node(event, node_name):
            return False

        text = f"{self._event_reason(event)} {self._event_message(event)}"
        if self._has_exclusion_markers(text):
            return False

        component = self._event_component(event)
        if component and component not in {"kubelet", "node-controller"}:
            return False

        return any(marker in text for marker in self.RUNTIME_OUTAGE_MARKERS)

    def _is_recovery_event(self, event: dict[str, Any], node_name: str) -> bool:
        if not self._event_targets_node(event, node_name):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)
        return reason == "nodeready" or "status is now: nodeready" in message

    def _recovery_time_from_condition(
        self,
        node: dict[str, Any],
        precursor_time: datetime,
    ) -> datetime | None:
        cond = self._ready_condition(node)
        if not cond:
            return None

        if str(cond.get("status", "")).lower() != "true":
            return None

        transition = cond.get("lastTransitionTime")
        if not isinstance(transition, str):
            return None

        try:
            recovered_at = parse_time(transition)
        except Exception:
            return None

        if recovered_at < precursor_time:
            return None
        return recovered_at

    def _is_pod_break_event(self, event: dict[str, Any], pod_name: str) -> bool:
        if not self._event_targets_pod(event, pod_name):
            return False

        text = f"{self._event_reason(event)} {self._event_message(event)}"
        if self._has_exclusion_markers(text):
            return False

        if self._event_reason(event) == "sandboxchanged":
            return True

        return any(marker in text for marker in self.BREAK_EVENT_MARKERS)

    def _pod_currently_impacted(self, pod: dict[str, Any]) -> bool:
        phase = pod.get("status", {}).get("phase")
        if phase == "Pending":
            return True

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if (status.get("restartCount", 0) or 0) >= 1:
                return True
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") in self.WAITING_REASONS:
                return True
        return False

    def _correlation(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        node_name: str,
        node: dict[str, Any],
    ) -> dict[str, Any] | None:
        pod_name = pod.get("metadata", {}).get("name", "")
        if not pod_name:
            return None

        ordered = self._ordered_events(timeline)
        precursor_events = [
            event
            for event in ordered
            if self._is_runtime_outage_precursor(event, node_name)
        ]
        if not precursor_events:
            return None

        if not self._pod_currently_impacted(pod):
            return None

        for precursor in precursor_events:
            precursor_time = self._extract_timestamp(precursor)
            if precursor_time is None:
                continue

            recovery_time = None
            for event in ordered:
                event_time = self._extract_timestamp(event)
                if event_time is None or event_time < precursor_time:
                    continue
                if self._is_recovery_event(event, node_name):
                    recovery_time = event_time
                    break

            if recovery_time is None:
                recovery_time = self._recovery_time_from_condition(node, precursor_time)

            if recovery_time is None:
                continue

            for event in ordered:
                event_time = self._extract_timestamp(event)
                if event_time is None or event_time < recovery_time:
                    continue
                if self._is_pod_break_event(event, pod_name):
                    return {
                        "precursor": precursor,
                        "recovery_time": recovery_time,
                        "break_event": event,
                    }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        candidate = self._candidate_node(pod, node_objs)
        if candidate is None:
            return False

        node_name, node = candidate
        correlation = self._correlation(pod, timeline, node_name, node)
        return correlation is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        candidate = self._candidate_node(pod, node_objs)
        if not isinstance(timeline, Timeline) or candidate is None:
            raise ValueError("RuntimeRestartBreaksPod requires node and timeline")

        node_name, node = candidate
        correlation = self._correlation(pod, timeline, node_name, node)
        if correlation is None:
            raise ValueError("RuntimeRestartBreaksPod explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        cond = self._ready_condition(node) or {}
        ready_status = str(cond.get("status", "Unknown"))
        ready_reason = str(cond.get("reason", "Unknown"))
        break_reason = str(correlation["break_event"].get("reason", "Unknown"))
        break_message = str(correlation["break_event"].get("message", "")).strip()

        restart_count = max(
            (
                int(status.get("restartCount", 0) or 0)
                for status in pod.get("status", {}).get("containerStatuses", []) or []
            ),
            default=0,
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="RUNTIME_OUTAGE_OBSERVED",
                    message="Timeline shows the node container runtime became unavailable before pod disruption",
                    role="temporal_context",
                ),
                Cause(
                    code="NODE_RUNTIME_RESTARTED",
                    message="The node container runtime restarted or recovered and destabilized the affected pod",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_OR_CONTAINER_DISRUPTED",
                    message="After runtime recovery, kubelet had to recreate or restart pod workload state",
                    role="control_loop",
                ),
                Cause(
                    code="POD_BROKEN_AFTER_RUNTIME_RESTART",
                    message="The pod remains unhealthy because runtime restart fallout interrupted its execution state",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container runtime restart on the node disrupted the pod after recovery",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Node runtime outage signal was observed before recovery on node {node_name}",
                f"Node Ready condition is currently {ready_status} (reason={ready_reason}), indicating the node recovered after the runtime interruption",
                f"Event: {break_reason}",
                "Pod disruption happened after the runtime recovered rather than during a still-active outage",
                *(
                    [
                        f"Pod restartCount increased to {restart_count} after the disruption"
                    ]
                    if restart_count > 0
                    else []
                ),
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    f"Ready condition={ready_status} reason={ready_reason}",
                    "Runtime outage was followed by node recovery before pod disruption",
                ],
                f"pod:{pod_name}": [
                    "Pod was disrupted after the node container runtime restarted or recovered",
                    *([break_message] if break_message else []),
                ],
            },
            "likely_causes": [
                "containerd or CRI-O restarted on the node and forced kubelet to recreate sandbox or container state",
                "A transient runtime outage left pod sandbox state inconsistent after recovery",
                "Host maintenance, runtime crash, or daemon upgrade restarted the runtime underneath a live workload",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                f"kubectl describe pod {pod_name}",
                "Inspect kubelet and containerd or CRI-O service restart history on the node",
                "Correlate pod sandbox change or restart timestamps with runtime daemon restarts",
            ],
        }
