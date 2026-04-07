from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeNetworkUnavailableRule(FailureRule):
    """
    Detects Pods blocked by a node that is explicitly marked
    NetworkUnavailable=True.

    Real-world interpretation:
    - the node is registered and may still report Ready=True
    - cloud route programming or node/CNI initialization has not completed
    - scheduler or kubelet signals show workload impact from the node's
      NetworkUnavailable condition

    Exclusions:
    - nodes whose primary issue is Ready=False/Unknown (handled by node-health rules)
    - pure container runtime failures
    - CNI IP exhaustion without a NetworkUnavailable condition
    """

    name = "NodeNetworkUnavailable"
    category = "Networking"
    priority = 33
    deterministic = True

    blocks = [
        "CNIPluginFailure",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
    }

    supported_phases = {"Pending", "Running", "Unknown"}

    WINDOW_MINUTES = 20

    CONDITION_REASON_MARKERS = {
        "nodenetworkunavailable",
        "networkunavailable",
        "noroutecreated",
        "routecreationfailed",
        "nocloudroute",
    }

    CONDITION_MESSAGE_MARKERS = (
        "network unavailable",
        "routecontroller failed to create a route",
        "failed to create a route to the node",
        "network plugin is not ready",
        "cni config uninitialized",
        "network not ready",
    )

    SCHEDULING_MESSAGE_MARKERS = (
        "condition {networkunavailable: true}",
        "condition {network unavailable: true}",
        "had condition {networkunavailable: true}",
        "network-unavailable",
        "node.kubernetes.io/network-unavailable",
    )

    POD_NETWORK_MARKERS = (
        "network plugin is not ready",
        "cni config uninitialized",
        "pod network",
        "network is not ready",
        "failed to set up pod network",
    )

    RUNTIME_EXCLUSION_MARKERS = (
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "runtime.v1.runtimeservice",
        "unsupported runtime api version",
        "runtime api version is not supported",
        "containerd.sock",
        "cri-o.sock",
    )

    IP_EXHAUSTION_EXCLUSION_MARKERS = (
        "no available ip",
        "no more ips",
        "address pool is exhausted",
        "ip pool exhausted",
        "failed to assign an ip address",
        "ipam",
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

    def _ready_status(self, node: dict[str, Any]) -> str | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "Ready":
                return str(cond.get("status", "Unknown"))
        return None

    def _network_condition(self, node: dict[str, Any]) -> dict[str, Any] | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "NetworkUnavailable":
                return cond
        return None

    def _network_unavailable_true(self, node: dict[str, Any]) -> bool:
        cond = self._network_condition(node)
        if not cond:
            return False
        return str(cond.get("status", "")).lower() == "true"

    def _specific_to_network_unavailable(self, node: dict[str, Any]) -> bool:
        ready_status = self._ready_status(node)
        return ready_status not in {"False", "Unknown"}

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
            if (
                str(involved.get("kind", "")).lower() == "node"
                and involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True
        return node_name.lower() in self._event_message(event)

    def _event_targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        pod_name = pod.get("metadata", {}).get("name")
        pod_ns = pod.get("metadata", {}).get("namespace")
        if not isinstance(involved, dict):
            return False
        if str(involved.get("kind", "")).lower() != "pod":
            return False
        if involved.get("name") != pod_name:
            return False
        if pod_ns and involved.get("namespace") and involved.get("namespace") != pod_ns:
            return False
        return True

    def _runtime_or_ip_excluded(self, event: dict[str, Any]) -> bool:
        text = f"{self._event_reason(event)} {self._event_message(event)}"
        return any(marker in text for marker in self.RUNTIME_EXCLUSION_MARKERS) or any(
            marker in text for marker in self.IP_EXHAUSTION_EXCLUSION_MARKERS
        )

    def _is_node_network_signal(
        self,
        event: dict[str, Any],
        node_name: str,
    ) -> bool:
        if self._runtime_or_ip_excluded(event):
            return False
        if not self._event_targets_node(event, node_name):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)
        component = self._event_component(event)

        if component and component not in {
            "node-controller",
            "kubelet",
            "cloud-node-controller",
        }:
            return False

        if reason in self.CONDITION_REASON_MARKERS:
            return True

        return any(marker in message for marker in self.CONDITION_MESSAGE_MARKERS)

    def _is_scheduler_network_signal(
        self,
        event: dict[str, Any],
        node_name: str,
    ) -> bool:
        if self._runtime_or_ip_excluded(event):
            return False
        if self._event_reason(event) != "failedscheduling":
            return False
        message = self._event_message(event)
        if not any(marker in message for marker in self.SCHEDULING_MESSAGE_MARKERS):
            return False
        if node_name in message:
            return True
        return "networkunavailable" in message or "network-unavailable" in message

    def _is_pod_network_symptom(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if self._runtime_or_ip_excluded(event):
            return False
        if not self._event_targets_pod(event, pod):
            return False
        reason = self._event_reason(event)
        message = self._event_message(event)
        if reason == "cnipluginfailure":
            return True
        if reason != "failedcreatepodsandbox":
            return False
        return any(marker in message for marker in self.POD_NETWORK_MARKERS)

    def _recent_events(
        self,
        timeline: Timeline | None,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if isinstance(timeline, Timeline):
            return self._ordered_events(
                timeline.events_within_window(self.WINDOW_MINUTES)
            )
        return self._ordered_events(events)

    def _condition_transition_recent(
        self, node: dict[str, Any], timeline: Timeline
    ) -> bool:
        cond = self._network_condition(node)
        if not cond:
            return False

        transition = cond.get("lastTransitionTime")
        if not isinstance(transition, str):
            return False

        try:
            transition_time = parse_time(transition)
        except Exception:
            return False

        reference = timeline._reference_time()
        return (reference - transition_time).total_seconds() <= self.WINDOW_MINUTES * 60

    def _find_match(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[str, dict[str, Any], str] | None:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return None

        timeline = context.get("timeline")
        recent_events = self._recent_events(timeline, events)
        pod_phase = pod.get("status", {}).get("phase")
        assigned_node = pod.get("spec", {}).get("nodeName")

        for node_name, node in self._candidate_nodes(pod, node_objs).items():
            if not self._network_unavailable_true(node):
                continue
            if not self._specific_to_network_unavailable(node):
                continue
            if assigned_node and assigned_node != node_name:
                continue

            has_node_signal = any(
                self._is_node_network_signal(event, node_name)
                for event in recent_events
            )
            has_scheduler_signal = any(
                self._is_scheduler_network_signal(event, node_name)
                for event in recent_events
            )
            has_pod_network_symptom = any(
                self._is_pod_network_symptom(event, pod) for event in recent_events
            )
            transition_recent = isinstance(
                timeline, Timeline
            ) and self._condition_transition_recent(
                node,
                timeline,
            )

            if assigned_node == node_name and (
                has_node_signal or has_pod_network_symptom or transition_recent
            ):
                impact = "pod_network_setup" if has_pod_network_symptom else "assigned"
                return node_name, node, impact

            if (
                pod_phase == "Pending"
                and not assigned_node
                and has_scheduler_signal
                and (has_node_signal or transition_recent)
            ):
                return node_name, node, "scheduling"

        return None

    def matches(self, pod, events, context) -> bool:
        return self._find_match(pod, events, context) is not None

    def explain(self, pod, events, context):
        match = self._find_match(pod, events, context)
        if match is None:
            raise ValueError(
                "NodeNetworkUnavailable explain() requires a matching NetworkUnavailable node"
            )

        node_name, node, impact = match
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        ready_status = self._ready_status(node) or "Unknown"
        condition = self._network_condition(node) or {}
        condition_reason = (
            str(condition.get("reason", "NetworkUnavailable")) or "NetworkUnavailable"
        )

        workload_message = (
            "Scheduler cannot place workload onto a node whose network is not available yet"
            if impact == "scheduling"
            else "Workload cannot rely on pod networking while its assigned node is NetworkUnavailable"
        )
        pod_evidence = (
            "Scheduler blocked pod placement due to NetworkUnavailable node condition"
            if impact == "scheduling"
            else "Pod is tied to a node marked NetworkUnavailable"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_NETWORK_CONDITION_ACTIVE",
                    message=f"Node reports NetworkUnavailable=True with Ready={ready_status}",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_NETWORK_UNAVAILABLE",
                    message="Node networking is not available for regular workload placement or pod network setup",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_BLOCKED_BY_NODE_NETWORK_STATE",
                    message=workload_message,
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "Node condition NetworkUnavailable=True",
            f"Node Ready condition remains {ready_status}",
            f"NetworkUnavailable condition reason: {condition_reason}",
        ]
        if impact == "scheduling":
            evidence.append(
                "Timeline contains FailedScheduling referencing NetworkUnavailable node condition or taint"
            )
        else:
            evidence.append(
                "Timeline contains node-controller or kubelet signal confirming node networking is unavailable"
            )

        object_evidence = {
            f"node:{node_name}": [
                "Node condition NetworkUnavailable=True",
                f"Node Ready condition={ready_status}",
            ],
            f"pod:{pod_name}": [pod_evidence],
        }

        return {
            "rule": self.name,
            "root_cause": "Node is marked NetworkUnavailable",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Cloud route programming has not completed for the node",
                "CNI daemon or node network bootstrap has not finished initialization",
                "The node registered before pod networking became available",
                "Cluster networking control-plane integration for the node is degraded",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Inspect node-controller or cloud-controller-manager logs for route programming failures",
                "Check CNI daemonset status on the affected node",
                f"kubectl describe pod {pod_name}",
            ],
        }
