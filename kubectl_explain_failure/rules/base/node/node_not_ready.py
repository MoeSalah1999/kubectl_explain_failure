from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeNotReadyRule(FailureRule):
    """
    Detects operational node readiness failures affecting an assigned Pod
    or blocking scheduling while candidate nodes are NotReady.

    Real-world interpretation:
    - Node Ready condition is False or Unknown
    - Kubelet health, node heartbeat, or node networking is degraded
    - For assigned Pods, the workload is running on or tied to an unhealthy node
    - For Pending Pods, scheduler/node-controller signals indicate NotReady nodes

    Exclusions:
    - Evicted pods caused by NotReady are handled by NodeNotReadyEvicted
    - This rule is meant for live node-health degradation, not completed eviction
    """

    name = "NodeNotReady"
    category = "Node"
    priority = 24
    deterministic = True
    blocks = [
        "FailedScheduling",
        "NodeDiskPressure",
        "NodeMemoryPressure",
        "NodePIDPressure",
        "EphemeralStorageExceeded",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

    NOT_READY_EVENT_MARKERS = (
        "node is not ready",
        "node not ready",
        "kubelet not ready",
        "node(s) were not ready",
        "node(s) not ready",
    )

    def _is_not_ready(self, node: dict) -> bool:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") != "Ready":
                continue
            status = str(cond.get("status", ""))
            if status in {"False", "Unknown"}:
                return True
        return False

    def _candidate_nodes(
        self, pod: dict, node_objs: dict[str, dict]
    ) -> dict[str, dict]:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return {assigned_node: node_objs[assigned_node]}
        return node_objs

    def _has_not_ready_timeline_signal(self, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        if timeline:
            for event in timeline.raw_events:
                reason = str(event.get("reason", "")).lower()
                message = str(event.get("message", "")).lower()
                if reason == "nodenotready":
                    return True
                if any(marker in message for marker in self.NOT_READY_EVENT_MARKERS):
                    return True
                if reason == "failedscheduling" and "not ready" in message:
                    return True

        for event in events:
            reason = str(event.get("reason", "")).lower()
            message = str(event.get("message", "")).lower()
            if reason == "nodenotready":
                return True
            if any(marker in message for marker in self.NOT_READY_EVENT_MARKERS):
                return True
        return False

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        not_ready_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._is_not_ready(node)
        }
        if not not_ready_nodes:
            return False

        pod_phase = pod.get("status", {}).get("phase")
        assigned_node = pod.get("spec", {}).get("nodeName")

        if assigned_node and assigned_node in not_ready_nodes:
            return True

        if pod_phase == "Pending":
            return self._has_not_ready_timeline_signal(events, context)

        return self._has_not_ready_timeline_signal(events, context)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        not_ready_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._is_not_ready(node)
        }

        assigned_node = pod.get("spec", {}).get("nodeName")
        node_names = sorted(not_ready_nodes.keys())
        readiness_status = "False"
        for node in not_ready_nodes.values():
            for cond in node.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready" and str(cond.get("status", "")) in {
                    "False",
                    "Unknown",
                }:
                    readiness_status = str(cond.get("status", "False"))
                    break

        evidence = [
            f"Node Ready condition is {readiness_status}",
            f"Affected node(s): {', '.join(node_names)}",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")
        if self._has_not_ready_timeline_signal(events, context):
            evidence.append(
                "Timeline contains NodeNotReady or equivalent kubelet readiness signal"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_READY_CONDITION_DEGRADED",
                    message=f"Node Ready condition is {readiness_status}",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_NOT_READY",
                    message="Node is NotReady due to kubelet or node-level health failure",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_IMPACTED_BY_NODE_UNAVAILABILITY",
                    message="Workload cannot run or schedule normally while the node is NotReady",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [f"Node Ready condition={readiness_status}"]
                for name in node_names
            }
        }
        object_evidence[f"pod:{pod_name}"] = [
            "Pod is affected by a NotReady node condition"
        ]

        return {
            "root_cause": "Node is NotReady",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet is stopped or unhealthy on the node",
                "Node heartbeat is failing or delayed",
                "Node network partition is preventing control-plane communication",
                "Underlying VM or host health is degraded",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "kubectl get nodes",
                "Check kubelet status and node heartbeats",
                f"kubectl describe pod {pod_name}",
            ],
        }
