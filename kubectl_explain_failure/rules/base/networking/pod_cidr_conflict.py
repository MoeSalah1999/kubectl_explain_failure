from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class PodCIDRConflictRule(FailureRule):
    """
    Detects nodes whose PodCIDR overlaps or conflicts with another node
    allocation, leaving node networking unable to converge.

    Real-world interpretation:
    - node IPAM or cluster networking control-plane assigned a PodCIDR that
      duplicates or overlaps another node allocation
    - controller events identify the CIDR allocation conflict
    - the affected node is typically marked NetworkUnavailable or otherwise
      unable to complete regular pod-network setup

    Exclusions:
    - cluster CIDR exhaustion without a conflicting allocation
    - generic CNI failures that do not implicate PodCIDR allocation
    - runtime outages unrelated to networking
    """

    name = "PodCIDRConflict"
    category = "Networking"
    priority = 36
    deterministic = True

    blocks = [
        "NodeNetworkUnavailable",
        "CNIPluginFailure",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    supported_phases = {"Pending", "Running", "Unknown"}

    WINDOW_MINUTES = 20

    CONFLICT_REASON_MARKERS = {
        "cidrnotavailable",
        "cidrallocationfailed",
        "podcidrconflict",
        "podcidrallocationfailed",
        "podcidrnotavailable",
    }

    CONFLICT_MESSAGE_MARKERS = (
        "podcidr",
        "pod cidr",
        "overlap",
        "overlaps with",
        "already allocated",
        "already assigned",
        "already in use",
        "duplicate cidr",
        "conflict",
    )

    EXHAUSTION_MARKERS = (
        "no remaining cidrs",
        "no remaining cidr",
        "cidr range is full",
        "range is full",
        "exhausted",
        "out of cidrs",
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

    def _node_pod_cidrs(self, node: dict[str, Any]) -> list[str]:
        spec = node.get("spec", {})
        cidrs: list[str] = []

        pod_cidr = spec.get("podCIDR")
        if isinstance(pod_cidr, str) and pod_cidr.strip():
            cidrs.append(pod_cidr.strip())

        pod_cidrs = spec.get("podCIDRs", [])
        if isinstance(pod_cidrs, list):
            for cidr in pod_cidrs:
                if isinstance(cidr, str) and cidr.strip():
                    cidrs.append(cidr.strip())

        return list(dict.fromkeys(cidrs))

    def _parse_network(self, cidr: str) -> ipaddress._BaseNetwork | None:
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return None

    def _find_conflicts(
        self,
        node_name: str,
        node: dict[str, Any],
        node_objs: dict[str, dict[str, Any]],
    ) -> list[tuple[str, str, str]]:
        target_cidrs = self._node_pod_cidrs(node)
        conflicts: list[tuple[str, str, str]] = []

        for target_cidr in target_cidrs:
            target_net = self._parse_network(target_cidr)
            if target_net is None:
                continue

            for other_name, other_node in node_objs.items():
                if other_name == node_name:
                    continue
                for other_cidr in self._node_pod_cidrs(other_node):
                    other_net = self._parse_network(other_cidr)
                    if other_net is None:
                        continue
                    if target_net.overlaps(other_net):
                        conflicts.append((other_name, target_cidr, other_cidr))

        return conflicts

    def _network_unavailable_true(self, node: dict[str, Any]) -> bool:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") != "NetworkUnavailable":
                continue
            if str(cond.get("status", "")).lower() == "true":
                return True
        return False

    def _is_conflict_event(self, event: dict[str, Any], node_name: str) -> bool:
        if not self._event_targets_node(event, node_name):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)
        component = self._event_component(event)
        text = f"{reason} {message}"

        if any(marker in text for marker in self.RUNTIME_EXCLUSION_MARKERS):
            return False
        if any(marker in text for marker in self.EXHAUSTION_MARKERS):
            return False
        if "cidr" not in text:
            return False

        if component and component not in {
            "kube-controller-manager",
            "node-controller",
            "route-controller",
            "cloud-node-controller",
        }:
            return False

        if reason in self.CONFLICT_REASON_MARKERS:
            return True

        return any(marker in message for marker in self.CONFLICT_MESSAGE_MARKERS)

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

    def _find_match(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> (
        tuple[str, dict[str, Any], list[tuple[str, str, str]], list[dict[str, Any]]]
        | None
    ):
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return None

        timeline = context.get("timeline")
        recent_events = self._recent_events(timeline, events)
        assigned_node = pod.get("spec", {}).get("nodeName")

        for node_name, node in self._candidate_nodes(pod, node_objs).items():
            if assigned_node and assigned_node != node_name:
                continue

            conflicts = self._find_conflicts(node_name, node, node_objs)
            conflict_events = [
                event
                for event in recent_events
                if self._is_conflict_event(event, node_name)
            ]

            if not conflicts and not conflict_events:
                continue

            # Require either concrete object-graph conflict plus recent controller
            # confirmation, or a recent node conflict event on a node already
            # marked NetworkUnavailable.
            if conflicts and conflict_events:
                return node_name, node, conflicts, conflict_events

            if self._network_unavailable_true(node) and conflict_events:
                return node_name, node, conflicts, conflict_events

        return None

    def matches(self, pod, events, context) -> bool:
        return self._find_match(pod, events, context) is not None

    def explain(self, pod, events, context):
        match = self._find_match(pod, events, context)
        if match is None:
            raise ValueError(
                "PodCIDRConflict explain() requires a conflicting node match"
            )

        node_name, node, conflicts, conflict_events = match
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        latest_event = conflict_events[-1] if conflict_events else {}
        latest_reason = str(latest_event.get("reason", "CIDRNotAvailable"))
        node_cidrs = self._node_pod_cidrs(node)
        primary_cidr = node_cidrs[0] if node_cidrs else "<unknown>"

        evidence = [
            f"Assigned node PodCIDR {primary_cidr} overlaps another node allocation",
            f"Latest relevant controller event reason: {latest_reason}",
            f"Observed {len(conflict_events)} recent PodCIDR conflict event(s) in the incident window",
        ]
        if self._network_unavailable_true(node):
            evidence.append(
                "Affected node is marked NetworkUnavailable while PodCIDR conflict is active"
            )

        object_evidence = {
            f"node:{node_name}": [
                f"Node PodCIDR={primary_cidr}",
            ],
            f"pod:{pod_name}": [
                "Pod is assigned to a node whose PodCIDR conflicts with another node allocation"
            ],
        }

        for other_name, target_cidr, other_cidr in conflicts:
            object_evidence[f"node:{node_name}"].append(
                f"PodCIDR {target_cidr} overlaps node {other_name} allocation {other_cidr}"
            )
            object_evidence.setdefault(f"node:{other_name}", []).append(
                f"Conflicts with node {node_name} PodCIDR {target_cidr}"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PODCIDR_ASSIGNED",
                    message=f"Node is assigned PodCIDR {primary_cidr}",
                    role="infrastructure_context",
                ),
                Cause(
                    code="POD_CIDR_CONFLICT",
                    message="Node PodCIDR overlaps another node allocation and prevents stable node networking",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_BLOCKED_BY_POD_CIDR_CONFLICT",
                    message="Workloads on the affected node cannot rely on normal pod networking while the PodCIDR conflict persists",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Node PodCIDR conflicts with another node allocation",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node IPAM assigned a duplicate or overlapping PodCIDR to multiple nodes",
                "Cluster CIDR configuration changed and left stale PodCIDR allocations behind",
                "A controller or cloud-network integration replayed an already-used PodCIDR range",
                "Node re-registration or restore logic reused a PodCIDR that was still active on another node",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Compare spec.podCIDR/spec.podCIDRs across nodes for duplicates or overlaps",
                "Inspect kube-controller-manager logs for node IPAM or CIDR allocation conflicts",
                f"kubectl describe pod {pod_name}",
            ],
        }
