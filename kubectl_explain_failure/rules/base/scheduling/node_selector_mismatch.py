from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeSelectorMismatchRule(FailureRule):
    """
    Detects scheduling failures when Pod.spec.nodeSelector cannot match any node labels.
    High-signal object-first scheduling failure.
    """

    name = "NodeSelectorMismatch"
    category = "Scheduling"
    priority = 16

    requires = {
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        pod_spec = pod.get("spec", {})
        node_selector = pod_spec.get("nodeSelector", {})
        node_objs = context.get("objects", {}).get("node", {})

        if not node_selector or not node_objs:
            return False

        # Check if any node satisfies all nodeSelector labels
        for node in node_objs.values():
            labels = node.get("metadata", {}).get("labels", {})
            if all(labels.get(k) == v for k, v in node_selector.items()):
                return False  # At least one match found

        # No matching nodes
        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_selector = pod.get("spec", {}).get("nodeSelector", {})
        node_objs = context.get("objects", {}).get("node", {})
        node_names = list(node_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_SELECTOR_MISMATCH",
                    message=f"No nodes match Pod.nodeSelector: {node_selector}",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod nodeSelector does not match any node labels",
            "confidence": 0.92,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod has nodeSelector {node_selector}, but no nodes satisfy all labels"
            ],
            "object_evidence": {
                f"pod:{pod_name}": [f"Pod nodeSelector {node_selector} mismatch"],
                **{
                    f"node:{name}": ["Node labels do not satisfy Pod nodeSelector"]
                    for name in node_names
                },
            },
            "likely_causes": [
                "NodeSelector specifies labels not present on any node",
                "Cluster labels misconfigured",
                "Pod scheduling constraints too strict",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Adjust pod nodeSelector or add matching labels to nodes",
            ],
        }
