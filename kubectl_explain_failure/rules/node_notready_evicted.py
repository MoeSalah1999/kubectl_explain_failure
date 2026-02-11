from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeNotReadyEvictedRule(FailureRule):
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
                    code="NODE_NOT_READY",
                    message="Node Ready condition is False",
                    blocking=True,
                ),
                Cause(
                    code="POD_EVICTED",
                    message="Pod evicted from node",
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
                f"kubectl describe node {not_ready_nodes[0]}"
                if not_ready_nodes
                else "kubectl describe node <node-name>",
                "kubectl get nodes",
                "Check kubelet service status on the node",
                f"kubectl describe pod {pod_name}",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": [
                        "Ready=False condition detected"
                    ]
                    for name in not_ready_nodes
                },
                f"pod:{pod_name}": [
                    "Evicted event observed"
                ],
            },
        }
