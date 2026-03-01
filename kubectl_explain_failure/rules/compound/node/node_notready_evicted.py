from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeNotReadyEvictedRule(FailureRule):
    """
    Detects Pods that were evicted because their hosting Node
    entered a NotReady state, triggering kubelet-driven eviction.

    Signals:
    - Node.status.conditions includes Ready=False
    - Pod has Event reason=Evicted
    - Node object present in context

    Interpretation:
    The Node hosting the Pod transitioned to NotReady,
    indicating kubelet unavailability or node-level failure.
    As a result, the control plane evicted Pods from the Node,
    causing termination independent of Pod configuration.

    Scope:
    - Infrastructure layer (Node health + kubelet state)
    - Deterministic (object-state + event correlation based)
    - Acts as a compound check to suppress generic eviction
    rules when Node health is the true cause

    Exclusions:
    - Does not include resource-pressure evictions (MemoryPressure, DiskPressure)
    - Does not include voluntary Pod deletion
    - Does not include scheduling failures unrelated to Node readiness
    """
    name = "NodeNotReadyEvicted"
    category = "Compound"
    priority = 59

    # Dominates generic eviction rules
    blocks = ["Evicted"]

    requires = {"objects": ["node"]}

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})

        node_not_ready = any(
            any(
                cond.get("type") == "Ready" and cond.get("status") == "False"
                for cond in node.get("status", {}).get("conditions", [])
            )
            for node in node_objs.values()
        )

        evicted = any(e.get("reason") == "Evicted" for e in events)

        return node_not_ready and evicted

    def explain(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})

        not_ready_nodes = [
            node.get("metadata", {}).get("name")
            for node in node_objs.values()
            if any(
                cond.get("type") == "Ready" and cond.get("status") == "False"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_READY_CONDITION_FALSE",
                    message="Node Ready condition is False",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_NOT_READY",
                    message="Node is NotReady due to kubelet or node-level failure",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_EVICTED",
                    message="Pod evicted as a result of NodeNotReady condition",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod evicted due to NodeNotReady condition",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Event: Evicted",
                "Node Ready condition = False",
            ],
            "likely_causes": [
                "Node heartbeat failure",
                "Kubelet stopped or unresponsive",
                "Node network partition",
                "Underlying node resource failure",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {not_ready_nodes[0]}"
                    if not_ready_nodes
                    else "kubectl describe node <node-name>"
                ),
                "kubectl get nodes",
                "Check kubelet service status on the node",
                f"kubectl describe pod {pod_name}",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": ["Ready=False condition detected"]
                    for name in not_ready_nodes
                },
                f"pod:{pod_name}": ["Evicted event observed"],
            },
        }
