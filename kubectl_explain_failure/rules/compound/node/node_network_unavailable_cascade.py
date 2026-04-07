from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeNetworkUnavailableCascadeRule(FailureRule):
    """
    Detects node-level network unavailability cascading into pod sandbox/network setup failure.

    Real-world interpretation:
    - the assigned node reports NetworkUnavailable=True
    - node-controller or kubelet emits a node-network-unavailable style signal
    - kubelet later fails pod sandbox/network setup on that node
    - the pod failure is downstream of node networking being unavailable,
      not merely a standalone CNI plugin symptom

    Exclusions:
    - pure container runtime outages or CRI API/version mismatch
    - CNI IP exhaustion without node network-unavailable condition
    - host-level heartbeat loss unrelated to node network setup
    """

    name = "NodeNetworkUnavailableCascade"
    category = "Compound"
    priority = 63
    deterministic = True

    blocks = [
        "CNIConfigMissing",
        "CNIPluginFailure",
        "NodeNetworkUnavailable",
        "PodCIDRConflict",
        "NodeNotReady",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    phases = ["Pending"]

    NETWORK_CONDITION_MARKERS = (
        "network is unavailable",
        "node network unavailable",
        "networkunavailable",
        "no route created",
        "route not created",
        "network plugin not ready",
        "cni config uninitialized",
        "network not ready",
    )

    RUNTIME_EXCLUSION_MARKERS = (
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "connection refused",
        "containerd.sock",
        "cri-o.sock",
        "runtime.v1.runtimeservice",
        "unknown service runtime.v1",
        "unsupported runtime api version",
        "runtime api version is not supported",
    )

    IP_EXHAUSTION_MARKERS = (
        "no available ip",
        "no more ips",
        "failed to assign an ip address",
        "ipam",
        "address pool is exhausted",
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

    def _candidate_nodes(
        self, pod: dict, node_objs: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return {assigned_node: node_objs[assigned_node]}
        return node_objs

    def _network_unavailable_true(self, node: dict[str, Any]) -> bool:
        return any(
            cond.get("type") == "NetworkUnavailable"
            and str(cond.get("status", "")).lower() == "true"
            for cond in node.get("status", {}).get("conditions", [])
        )

    def _network_transition_before_failure(
        self,
        node: dict[str, Any],
        failure_time: datetime | None,
    ) -> bool:
        if failure_time is None:
            return False

        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") != "NetworkUnavailable":
                continue
            if str(cond.get("status", "")).lower() != "true":
                continue

            transition = cond.get("lastTransitionTime")
            if not isinstance(transition, str):
                continue

            try:
                if parse_time(transition) <= failure_time:
                    return True
            except Exception:
                continue

        return False

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _has_runtime_exclusion(self, event: dict[str, Any]) -> bool:
        text = f"{self._event_reason(event)} {self._event_message(event)}"
        return any(marker in text for marker in self.RUNTIME_EXCLUSION_MARKERS)

    def _has_ip_exhaustion_exclusion(self, event: dict[str, Any]) -> bool:
        text = f"{self._event_reason(event)} {self._event_message(event)}"
        return any(marker in text for marker in self.IP_EXHAUSTION_MARKERS)

    def _is_network_precursor(self, event: dict[str, Any]) -> bool:
        component = self._event_component(event)
        if component and component not in {"node-controller", "kubelet"}:
            return False

        if self._has_runtime_exclusion(event) or self._has_ip_exhaustion_exclusion(
            event
        ):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason in {"nodenetworkunavailable", "networkunavailable"}:
            return True

        return any(marker in message for marker in self.NETWORK_CONDITION_MARKERS)

    def _is_network_failure_symptom(self, event: dict[str, Any]) -> bool:
        if self._has_runtime_exclusion(event) or self._has_ip_exhaustion_exclusion(
            event
        ):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason == "cnipluginfailure":
            return True

        if reason == "failedcreatepodsandbox" and (
            "cni" in message or "network plugin" in message or "pod network" in message
        ):
            return True

        return False

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

        node_name, node = next(iter(candidate_nodes.items()))
        if not self._network_unavailable_true(node):
            return False

        ordered = self._ordered_events(timeline)
        symptom_events = [
            event for event in ordered if self._is_network_failure_symptom(event)
        ]
        if not symptom_events:
            return False

        first_symptom = symptom_events[0]
        failure_time = self._extract_timestamp(first_symptom)
        precursor_seen = False
        for event in ordered:
            if event is first_symptom:
                break
            if self._is_network_precursor(event):
                precursor_seen = True
                break

        if not precursor_seen and not self._network_transition_before_failure(
            node, failure_time
        ):
            return False

        # Prefer node-unavailable cascade only when the pod is actually tied to the affected node.
        pod_node = pod.get("spec", {}).get("nodeName")
        if pod_node and pod_node != node_name:
            return False

        return True

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name, node = next(iter(candidate_nodes.items()))
        node = node or {}

        ordered = (
            self._ordered_events(timeline) if isinstance(timeline, Timeline) else []
        )
        symptom_event = next(
            (event for event in ordered if self._is_network_failure_symptom(event)),
            {},
        )
        symptom_message = str(symptom_event.get("message", "")).strip()

        symptom_reason = str(symptom_event.get("reason", "FailedCreatePodSandBox"))

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_NETWORK_UNAVAILABLE_ACTIVE",
                    message="Node reports NetworkUnavailable=True before pod network setup failed",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_NETWORK_UNAVAILABLE_CASCADE",
                    message="Node-level network unavailability cascaded into kubelet sandbox networking failure",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_NETWORK_SETUP_BLOCKED",
                    message="Pod sandbox and network attachment could not complete on the affected node",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "Node condition NetworkUnavailable=True",
            f"Event: {symptom_reason}",
            "Node network unavailable signal observed before pod network failure",
        ]
        if symptom_message:
            evidence.append("Sandbox or CNI event indicates pod network setup failure")

        object_evidence = {
            f"node:{node_name}": [
                "NetworkUnavailable=True before pod sandbox/network failure",
            ],
            f"pod:{pod_name}": [
                "Pod network setup failed after node network became unavailable",
            ],
        }
        if symptom_message:
            object_evidence[f"pod:{pod_name}"].append(symptom_message)

        return {
            "rule": self.name,
            "root_cause": "Node network unavailable condition cascaded into pod network setup failure",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Cloud route or node route programming did not complete for the node",
                "Node network plugin initialization left the node marked NetworkUnavailable",
                "Kubelet could not attach pod networking because node-level networking was not ready",
                "Node bootstrap or CNI daemon startup lag left the node unable to provide pod network paths",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                f"kubectl describe pod {pod_name}",
                "Inspect node-controller and CNI daemon logs for route or network initialization failures",
                "Check whether the node remains marked NetworkUnavailable and whether routes were programmed",
            ],
        }
