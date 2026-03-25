from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodePressureEvictionCascadeRule(FailureRule):
    """
    Detects node resource pressure that escalates into kubelet-driven pod eviction.

    Real-world model:
    - the pod is already bound to a node
    - that node reports active pressure (memory, disk, or PID)
    - kubelet later evicts the pod
    - the eviction is pressure-driven, not NodeNotReady-driven

    This is more specific than generic Evicted and more complete than the
    pressure-only node rules because it captures the escalation from
    infrastructure degradation into workload termination.
    """

    name = "NodePressureEvictionCascade"
    category = "Compound"
    priority = 78
    phases = ["Failed"]
    deterministic = True

    blocks = [
        "Evicted",
        "NodeMemoryPressure",
        "NodeDiskPressure",
        "NodePIDPressure",
        "ConflictingNodeConditions",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    PRESSURE_TYPES = ("MemoryPressure", "DiskPressure", "PIDPressure")
    PRESSURE_REASON_MARKERS = (
        "nodehasinsufficientmemory",
        "kubelethasinsufficientmemory",
        "nodehasdiskpressure",
        "kubelethasdiskpressure",
        "nodehasnodiskspace",
        "kubelethasnodiskspace",
        "nodehasinsufficientpid",
        "kubelethasinsufficientpid",
        "evictionthresholdmet",
    )
    PRESSURE_MESSAGE_MARKERS = (
        "low on resource: memory",
        "low on resource: ephemeral-storage",
        "low on resource: pid",
        "node had condition: [memorypressure]",
        "node had condition: [diskpressure]",
        "node had condition: [pidpressure]",
        "insufficient memory",
        "insufficient pid",
        "disk pressure",
        "memory pressure",
        "pid pressure",
        "eviction manager",
    )

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

    def _pressure_true(self, node: dict[str, Any], pressure_type: str) -> bool:
        return any(
            cond.get("type") == pressure_type
            and str(cond.get("status", "")).lower() == "true"
            for cond in node.get("status", {}).get("conditions", [])
        )

    def _ready_not_ready(self, node: dict[str, Any]) -> bool:
        return any(
            cond.get("type") == "Ready"
            and str(cond.get("status", "")).lower() in {"false", "unknown"}
            for cond in node.get("status", {}).get("conditions", [])
        )

    def _active_pressures(self, node: dict[str, Any]) -> list[str]:
        return [
            pressure
            for pressure in self.PRESSURE_TYPES
            if self._pressure_true(node, pressure)
        ]

    def _pressure_transition_before_eviction(
        self,
        node: dict[str, Any],
        eviction_time: datetime | None,
    ) -> bool:
        if eviction_time is None:
            return False

        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") not in self.PRESSURE_TYPES:
                continue
            if str(cond.get("status", "")).lower() != "true":
                continue

            transition = cond.get("lastTransitionTime")
            if not isinstance(transition, str):
                continue

            try:
                if parse_time(transition) <= eviction_time:
                    return True
            except Exception:
                continue

        return False

    def _event_indicates_pressure(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason", "")).lower()
        message = str(event.get("message", "")).lower()

        return any(marker in reason for marker in self.PRESSURE_REASON_MARKERS) or any(
            marker in message for marker in self.PRESSURE_MESSAGE_MARKERS
        )

    def _pod_node(
        self, pod: dict[str, Any], node_objs: dict[str, dict[str, Any]]
    ) -> tuple[str | None, dict[str, Any] | None]:
        node_name = pod.get("spec", {}).get("nodeName")
        if isinstance(node_name, str) and node_name in node_objs:
            return node_name, node_objs[node_name]
        if len(node_objs) == 1:
            only_name, only_node = next(iter(node_objs.items()))
            return only_name, only_node
        return None, None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        node_name, node = self._pod_node(pod, node_objs)
        if not node_name or not node:
            return False

        if self._ready_not_ready(node):
            return False

        active_pressures = self._active_pressures(node)
        if not active_pressures:
            return False

        ordered = self._ordered_events(timeline)
        evicted_events = [
            event for event in ordered if event.get("reason") == "Evicted"
        ]
        if not evicted_events:
            return False

        first_eviction = evicted_events[0]
        eviction_time = self._extract_timestamp(first_eviction)

        precursor_seen = False
        for event in ordered:
            if event is first_eviction:
                break
            if self._event_indicates_pressure(event):
                precursor_seen = True
                break

        eviction_mentions_pressure = self._event_indicates_pressure(first_eviction)
        condition_precedes_eviction = self._pressure_transition_before_eviction(
            node, eviction_time
        )

        return eviction_mentions_pressure and (
            precursor_seen or condition_precedes_eviction
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name, node = self._pod_node(pod, node_objs)
        node = node or {}
        active_pressures = self._active_pressures(node)
        pressure_list = ", ".join(active_pressures) if active_pressures else "unknown"

        ordered = (
            self._ordered_events(timeline) if isinstance(timeline, Timeline) else []
        )
        evicted_event = next(
            (event for event in ordered if event.get("reason") == "Evicted"),
            {},
        )
        eviction_message = str(evicted_event.get("message", "")).strip()

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PRESSURE_ACTIVE",
                    message=f"Node reports active pressure condition(s): {pressure_list}",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_PRESSURE_EVICTION_CASCADE",
                    message="Sustained node pressure escalated into kubelet-driven eviction",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_EVICTED_DUE_TO_NODE_PRESSURE",
                    message="Pod was evicted after node pressure crossed kubelet thresholds",
                    role="workload_termination",
                ),
            ]
        )

        evidence = [
            f"Active node pressure conditions: {pressure_list}",
            "Event: Evicted",
        ]
        if eviction_message:
            evidence.append("Eviction event message indicates node resource pressure")

        object_evidence = {
            f"node:{node_name or '<node>'}": [
                f"Pressure conditions active: {pressure_list}",
            ],
            f"pod:{pod_name}": [
                "Evicted event observed after node pressure activation",
            ],
        }
        if eviction_message:
            object_evidence[f"pod:{pod_name}"].append(eviction_message)

        return {
            "rule": self.name,
            "root_cause": "Node resource pressure escalated into kubelet eviction cascade",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node memory exhaustion crossed kubelet eviction thresholds",
                "Node disk or ephemeral-storage pressure forced workload reclamation",
                "PID pressure exhausted node process capacity",
                "Co-located workloads consumed node resources faster than recovery",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_name}"
                    if node_name
                    else "kubectl describe node <node-name>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check kubelet eviction thresholds and recent node pressure transitions",
                "Inspect node memory, disk, and PID usage around the eviction window",
            ],
        }
