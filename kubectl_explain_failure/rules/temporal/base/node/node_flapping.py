from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeFlappingRule(FailureRule):
    """
    Detects nodes that repeatedly alternate between Ready and NotReady within
    a bounded time window, causing unstable workload placement or execution.

    Real-world interpretation:
    - node-controller or kubelet emits repeated NodeReady/NodeNotReady changes
    - the same node does not stay healthy long enough to stabilize workloads
    - this is a temporal instability pattern, not a specific infrastructure root
      cause by itself

    Exclusions:
    - repeated kubelet startup/re-registration is handled by KubeletRestartLoop
    - single persistent NotReady condition is handled by NodeNotReady
    """

    name = "NodeFlapping"
    category = "Temporal"
    priority = 61
    deterministic = False

    blocks = [
        "NodeNotReady",
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

    STARTUP_REASONS = {"starting", "registerednode"}
    READY_REASONS = {"nodeready"}
    NOTREADY_REASONS = {"nodenotready"}

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
            if str(involved.get("kind", "")).lower() == "node" and (
                involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True

        message = self._event_message(event)
        return node_name.lower() in message

    def _classification(self, event: dict[str, Any]) -> str | None:
        reason = self._event_reason(event)
        if reason in self.READY_REASONS:
            return "ready"
        if reason in self.NOTREADY_REASONS:
            return "notready"
        return None

    def _collapsed_sequence(self, events: list[dict[str, Any]]) -> list[str]:
        sequence: list[str] = []
        for event in events:
            state = self._classification(event)
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

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        if not candidate_nodes:
            return False

        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        ordered = self._ordered_events(recent)

        # Defer to KubeletRestartLoop when repeated startup/re-registration exists.
        startup_count = sum(
            1 for event in ordered if self._event_reason(event) in self.STARTUP_REASONS
        )
        if startup_count >= 2:
            return False

        for node_name, node in candidate_nodes.items():
            node_events = [
                event
                for event in ordered
                if self._classification(event) is not None
                and self._event_targets_node(event, node_name)
            ]
            if len(node_events) < self.MIN_EVENTS:
                continue

            ready_count = sum(
                1 for event in node_events if self._classification(event) == "ready"
            )
            notready_count = sum(
                1 for event in node_events if self._classification(event) == "notready"
            )

            if ready_count < 2 or notready_count < 2:
                continue

            sequence = self._collapsed_sequence(node_events)
            if len(sequence) < 4:
                continue
            if sequence[:4] != ["ready", "notready", "ready", "notready"] and sequence[
                :4
            ] != ["notready", "ready", "notready", "ready"]:
                alternating = True
                for idx in range(1, len(sequence)):
                    if sequence[idx] == sequence[idx - 1]:
                        alternating = False
                        break
                if not alternating:
                    continue

            duration = self._duration_seconds(node_events)
            if duration < self.MIN_DURATION_SECONDS:
                continue

            conds = node.get("status", {}).get("conditions", [])
            if not any(cond.get("type") == "Ready" for cond in conds):
                continue

            return True

        return False

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)

        node_name = next(iter(candidate_nodes), "<node>")
        node = candidate_nodes.get(node_name, {})
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        recent = (
            timeline.events_within_window(self.WINDOW_MINUTES)
            if isinstance(timeline, Timeline)
            else []
        )
        ordered = self._ordered_events(recent)
        node_events = [
            event
            for event in ordered
            if self._classification(event) is not None
            and self._event_targets_node(event, node_name)
        ]
        sequence = self._collapsed_sequence(node_events)
        duration = self._duration_seconds(node_events)

        ready_cond: dict[str, Any] = next(
            (
                cond
                for cond in node.get("status", {}).get("conditions", [])
                if cond.get("type") == "Ready"
            ),
            {},
        )
        ready_status = str(ready_cond.get("status", "Unknown"))
        ready_reason = str(ready_cond.get("reason", "Unknown"))

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_READY_STATE_OSCILLATION_OBSERVED",
                    message=f"Timeline shows repeated node readiness transitions: {' -> '.join(sequence)}",
                    role="temporal_context",
                ),
                Cause(
                    code="NODE_FLAPPING",
                    message="Node repeatedly alternated between Ready and NotReady states",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_UNSTABLE_DUE_TO_NODE_FLAPPING",
                    message="Workloads are unstable because the assigned node does not remain healthy long enough to converge",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Node readiness is flapping and causing workload instability",
            "confidence": 0.88,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Node readiness transitions observed: {' -> '.join(sequence)}",
                f"Node flapping persisted for {duration/60:.1f} minutes",
                f"Current Ready condition is {ready_status} (reason={ready_reason})",
                f"Observed {len(node_events)} NodeReady/NodeNotReady events within {self.WINDOW_MINUTES} minutes",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    f"Ready condition={ready_status} reason={ready_reason}",
                    "Repeated NodeReady and NodeNotReady transitions observed",
                ],
                f"pod:{pod_name}": [
                    "Pod is assigned to a node whose readiness repeatedly changed"
                ],
            },
            "likely_causes": [
                "Intermittent node connectivity or host instability is repeatedly breaking kubelet health",
                "Node control-plane communication is repeatedly recovering and failing",
                "Underlying node resource or infrastructure instability is causing readiness oscillation",
                "The node is repeatedly crossing health thresholds faster than workloads can stabilize",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Inspect recent NodeReady and NodeNotReady events in order",
                "Check kubelet logs and node health metrics around each transition",
                f"kubectl describe pod {pod_name}",
            ],
        }
