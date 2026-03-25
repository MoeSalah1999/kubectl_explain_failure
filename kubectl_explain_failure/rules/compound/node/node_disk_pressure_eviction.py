from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeDiskPressureThenEvictionRule(FailureRule):
    """
    Detects kubelet eviction that was preceded by node DiskPressure.

    Real-world model:
    - the pod is already running on a node
    - kubelet/node reports DiskPressure on that same node
    - DiskPressure occurs before the first eviction signal
    - kubelet later evicts the pod due to disk or ephemeral-storage pressure

    This is intentionally narrower than the generic node pressure eviction
    cascade because it requires disk-specific evidence plus ordering.
    """

    name = "NodeDiskPressureThenEviction"
    category = "Compound"
    priority = 79
    phases = ["Failed"]
    deterministic = True

    blocks = [
        "Evicted",
        "EphemeralStorageExceeded",
        "NodePressureEvictionCascade",
        "ConflictingNodeConditions",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    DISK_PRESSURE_REASON_MARKERS = (
        "nodehasdiskpressure",
        "kubelethasdiskpressure",
        "nodehasnodiskspace",
        "kubelethasnodiskspace",
    )
    DISK_PRESSURE_MESSAGE_MARKERS = (
        "low on resource: ephemeral-storage",
        "ephemeral-storage",
        "disk pressure",
        "node had condition: [diskpressure]",
        "nodefs",
        "imagefs",
        "reclaim ephemeral-storage",
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

    def _pod_node(
        self,
        pod: dict[str, Any],
        node_objs: dict[str, dict[str, Any]],
    ) -> tuple[str | None, dict[str, Any] | None]:
        node_name = pod.get("spec", {}).get("nodeName")
        if isinstance(node_name, str) and node_name in node_objs:
            return node_name, node_objs[node_name]
        if len(node_objs) == 1:
            only_name, only_node = next(iter(node_objs.items()))
            return only_name, only_node
        return None, None

    def _ready_not_ready(self, node: dict[str, Any]) -> bool:
        return any(
            cond.get("type") == "Ready"
            and str(cond.get("status", "")).lower() in {"false", "unknown"}
            for cond in node.get("status", {}).get("conditions", [])
        )

    def _disk_pressure_true(self, node: dict[str, Any]) -> bool:
        return any(
            cond.get("type") == "DiskPressure"
            and str(cond.get("status", "")).lower() == "true"
            for cond in node.get("status", {}).get("conditions", [])
        )

    def _disk_pressure_transition_before_eviction(
        self,
        node: dict[str, Any],
        eviction_time: datetime | None,
    ) -> bool:
        if eviction_time is None:
            return False

        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") != "DiskPressure":
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

    def _event_indicates_disk_pressure(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason", "")).lower()
        message = str(event.get("message", "")).lower()

        return any(
            marker in reason for marker in self.DISK_PRESSURE_REASON_MARKERS
        ) or any(marker in message for marker in self.DISK_PRESSURE_MESSAGE_MARKERS)

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

        if not self._disk_pressure_true(node):
            return False

        ordered = self._ordered_events(timeline)
        evicted_events = [
            event for event in ordered if event.get("reason") == "Evicted"
        ]
        if not evicted_events:
            return False

        first_eviction = evicted_events[0]
        if not self._event_indicates_disk_pressure(first_eviction):
            return False

        eviction_time = self._extract_timestamp(first_eviction)
        precursor_seen = False
        for event in ordered:
            if event is first_eviction:
                break
            if self._event_indicates_disk_pressure(event):
                precursor_seen = True
                break

        condition_precedes_eviction = self._disk_pressure_transition_before_eviction(
            node,
            eviction_time,
        )

        return precursor_seen or condition_precedes_eviction

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name, node = self._pod_node(pod, node_objs)
        node = node or {}

        ordered = (
            self._ordered_events(timeline) if isinstance(timeline, Timeline) else []
        )
        evicted_event = next(
            (event for event in ordered if event.get("reason") == "Evicted"),
            {},
        )
        eviction_message = str(evicted_event.get("message", "")).strip()

        precursor_seen = False
        for event in ordered:
            if event is evicted_event:
                break
            if self._event_indicates_disk_pressure(event):
                precursor_seen = True
                break

        evidence = [
            "Node condition DiskPressure=True",
            "Event: Evicted",
        ]
        if precursor_seen:
            evidence.append("Disk pressure signal observed before eviction")
        if eviction_message:
            evidence.append(
                "Eviction event message indicates disk or ephemeral-storage pressure"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_DISK_PRESSURE_ACTIVE",
                    message="Node reports DiskPressure=True before eviction",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_DISK_PRESSURE_EVICTION",
                    message="Sustained node disk pressure escalated into kubelet eviction",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_EVICTED_DUE_TO_DISK_PRESSURE",
                    message="Pod was evicted after node disk pressure crossed eviction thresholds",
                    role="workload_termination",
                ),
            ]
        )

        object_evidence = {
            f"node:{node_name or '<node>'}": [
                "DiskPressure=True before pod eviction",
            ],
            f"pod:{pod_name}": [
                "Evicted after node disk pressure was reported",
            ],
        }
        if eviction_message:
            object_evidence[f"pod:{pod_name}"].append(eviction_message)

        return {
            "rule": self.name,
            "root_cause": "Node DiskPressure escalated into kubelet eviction",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node ephemeral-storage consumption crossed kubelet eviction thresholds",
                "Container logs or writable layers exhausted node disk",
                "Image garbage collection could not reclaim enough space",
                "nodefs or imagefs pressure forced kubelet to reclaim workloads",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_name}"
                    if node_name
                    else "kubectl describe node <node-name>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check nodefs/imagefs usage and kubelet eviction thresholds",
                "Inspect container log growth and ephemeral-storage requests or limits",
            ],
        }
