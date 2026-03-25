from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeConditionOscillationRule(FailureRule):
    """
    Detects node condition families that repeatedly alternate between active
    pressure and recovery states within a short window.

    Example:
    NodeReady -> NodeHasInsufficientMemory -> NodeReady -> NodeHasInsufficientMemory

    Real-world interpretation:
    - the node repeatedly crosses a pressure threshold and then recovers
    - workloads see unstable placement or runtime behavior while the node
      oscillates instead of converging on a stable state
    - this is more informative than reporting only the final pressure state
    """

    name = "NodeConditionOscillation"
    category = "Temporal"
    priority = 66
    deterministic = False

    blocks = [
        "NodeMemoryPressure",
        "NodeDiskPressure",
        "NodePIDPressure",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    supported_phases = {"Pending", "Running", "Unknown"}

    WINDOW_MINUTES = 20
    MIN_EVENTS = 4
    MIN_DURATION_SECONDS = 180

    FAMILY_EVENT_MARKERS = {
        "MemoryPressure": {
            "active_reasons": {
                "nodehasinsufficientmemory",
                "kubelethasinsufficientmemory",
                "nodememorypressure",
            },
            "recovered_reasons": {
                "nodehassufficientmemory",
                "kubelethassufficientmemory",
                "nodeready",
            },
            "active_markers": (
                "memorypressure",
                "insufficient memory",
                "node has memory pressure",
            ),
        },
        "DiskPressure": {
            "active_reasons": {
                "nodehasnodiskspace",
                "nodehasdiskpressure",
                "kubelethasnodiskspace",
                "kubelethasdiskpressure",
                "nodediskpressure",
            },
            "recovered_reasons": {
                "nodehassufficientdisk",
                "kubelethassufficientdisk",
                "nodeready",
            },
            "active_markers": (
                "diskpressure",
                "no disk space",
                "disk pressure",
                "nodefs",
                "imagefs",
            ),
        },
        "PIDPressure": {
            "active_reasons": {
                "nodehasinsufficientpid",
                "kubelethasinsufficientpid",
                "nodepidpressure",
            },
            "recovered_reasons": {
                "nodehassufficientpid",
                "kubelethassufficientpid",
                "nodeready",
            },
            "active_markers": (
                "pidpressure",
                "insufficient pid",
                "pid pressure",
            ),
        },
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

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enumerated = list(enumerate(events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._extract_timestamp(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _candidate_nodes(
        self,
        pod: dict[str, Any],
        node_objs: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return {assigned_node: node_objs[assigned_node]}
        return node_objs

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_targets_node(self, event: dict[str, Any], node_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if (
                str(involved.get("kind", "")).lower() == "node"
                and involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True
        return node_name.lower() in self._event_message(event)

    def _classify_family(self, event: dict[str, Any], family: str) -> str | None:
        spec = self.FAMILY_EVENT_MARKERS[family]
        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason in spec["active_reasons"]:
            return "active"
        if reason in spec["recovered_reasons"]:
            return "recovered"
        if any(marker in message for marker in spec["active_markers"]):
            return "active"
        if "status is now: nodeready" in message:
            return "recovered"
        return None

    def _collapsed_sequence(
        self,
        events: list[dict[str, Any]],
        family: str,
    ) -> list[str]:
        sequence: list[str] = []
        for event in events:
            state = self._classify_family(event, family)
            if state is None:
                continue
            if not sequence or sequence[-1] != state:
                sequence.append(state)
        return sequence

    def _duration_seconds(self, events: list[dict[str, Any]]) -> float:
        if len(events) < 2:
            return 0.0
        first_ts = self._extract_timestamp(events[0])
        last_ts = self._extract_timestamp(events[-1])
        if first_ts is None or last_ts is None:
            return 0.0
        return (last_ts - first_ts).total_seconds()

    def _family_condition_status(self, node: dict[str, Any], family: str) -> str | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == family:
                return str(cond.get("status", "Unknown"))
        return None

    def _best_family(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[str, str, list[dict[str, Any]], list[str], float] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return None

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        if not candidate_nodes:
            return None

        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        ordered = self._ordered_events(recent)

        best: tuple[str, str, list[dict[str, Any]], list[str], float] | None = None
        best_score = (-1, -1.0)

        for node_name, node in candidate_nodes.items():
            for family in self.FAMILY_EVENT_MARKERS:
                if self._family_condition_status(node, family) is None:
                    continue

                family_events = [
                    event
                    for event in ordered
                    if self._event_targets_node(event, node_name)
                    and self._classify_family(event, family) is not None
                ]
                if len(family_events) < self.MIN_EVENTS:
                    continue

                active_count = sum(
                    1
                    for event in family_events
                    if self._classify_family(event, family) == "active"
                )
                recovered_count = sum(
                    1
                    for event in family_events
                    if self._classify_family(event, family) == "recovered"
                )
                if active_count < 2 or recovered_count < 2:
                    continue

                sequence = self._collapsed_sequence(family_events, family)
                if len(sequence) < 4:
                    continue

                alternating = True
                for idx in range(1, len(sequence)):
                    if sequence[idx] == sequence[idx - 1]:
                        alternating = False
                        break
                if not alternating:
                    continue

                duration = self._duration_seconds(family_events)
                if duration < self.MIN_DURATION_SECONDS:
                    continue

                score = (len(sequence), duration)
                if score > best_score:
                    best_score = score
                    best = (node_name, family, family_events, sequence, duration)

        return best

    def matches(self, pod, events, context) -> bool:
        return self._best_family(pod, context) is not None

    def explain(self, pod, events, context):
        best = self._best_family(pod, context)
        if best is None:
            raise ValueError(
                "NodeConditionOscillation requires an oscillating node condition family"
            )

        node_name, family, family_events, sequence, duration = best
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node = context.get("objects", {}).get("node", {}).get(node_name, {})
        current_status = self._family_condition_status(node, family) or "Unknown"

        family_label = family
        sequence_label = " -> ".join(
            family_label if state == "active" else "NodeReady" for state in sequence
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_CONDITION_OSCILLATION_OBSERVED",
                    message=f"Timeline shows repeated transitions between NodeReady and {family_label}",
                    role="temporal_context",
                ),
                Cause(
                    code="NODE_CONDITION_OSCILLATION",
                    message=f"Node repeatedly crossed the {family_label} threshold and recovered",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_UNSTABLE_DUE_TO_NODE_CONDITION_THRASHING",
                    message="Workloads are unstable because node health signals do not converge on a stable operating state",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": f"Node condition oscillated between Ready and {family_label} states",
            "confidence": 0.89,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Node condition transitions observed: {sequence_label}",
                f"{family_label} oscillation persisted for {duration/60:.1f} minutes",
                f"Current {family_label} condition status is {current_status}",
                f"Observed {len(family_events)} node condition transition events within {self.WINDOW_MINUTES} minutes",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    f"{family_label} condition status={current_status}",
                    f"Repeated NodeReady and {family_label} transitions observed",
                ],
                f"pod:{pod_name}": [
                    "Pod is assigned to a node whose health condition repeatedly oscillated"
                ],
            },
            "likely_causes": [
                "Node resource pressure is repeatedly crossing the recovery threshold",
                "Competing workloads or system daemons are causing unstable node pressure recovery",
                "The node recovers briefly and then re-enters pressure before workloads can stabilize",
                "Underlying host instability is causing repeated pressure and recovery cycles",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Inspect recent node condition transition events in order",
                "Check node resource usage trends around each pressure transition",
                f"kubectl describe pod {pod_name}",
            ],
        }
