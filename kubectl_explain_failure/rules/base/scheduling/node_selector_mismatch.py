from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeSelectorMismatchRule(FailureRule):
    """
    Detects Pod scheduling failures caused by nodeSelector label mismatch.

    Signals:
    - Pod.spec.nodeSelector is defined
    - No cluster node satisfies all specified label constraints

    Interpretation:
    The Pod declares strict node label requirements via nodeSelector, 
    but no available node in the cluster matches all required labels. 
    The scheduler cannot place the Pod, leaving it in a Pending state.

    Scope:
    - Scheduler phase
    - Deterministic (object-state based)
    - Captures hard label constraint mismatches

    Exclusions:
    - Does not include node affinity (requiredDuringSchedulingIgnoredDuringExecution)
    - Does not include taints and tolerations
    - Does not include resource insufficiency failures
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
                    code="POD_NODE_SELECTOR_DEFINED",
                    message=f"Pod declares nodeSelector constraints: {node_selector}",
                    role="workload_context",
                ),
                Cause(
                    code="NODE_SELECTOR_MISMATCH",
                    message="No available node satisfies all required label constraints",
                    role="infrastructure_root",
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_NODE_SELECTOR",
                    message="Scheduler cannot place Pod due to nodeSelector mismatch",
                    blocking=True,
                    role="scheduler_symptom",
                ),
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
