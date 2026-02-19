from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class AffinityUnsatisfiableRule(FailureRule):
    """
    Detects pod scheduling failures caused by affinity/anti-affinity constraints.
    Triggered when Pod.spec.affinity exists and scheduling failed.
    """

    name = "AffinityUnsatisfiable"
    category = "Scheduling"
    priority = 17
    blocks = ["FailedScheduling"]
    requires = {
        "context": ["timeline"],
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        affinity = pod.get("spec", {}).get("affinity")
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})

        if not affinity or not timeline or not node_objs:
            return False

        # Check scheduling failure events
        return timeline_has_pattern(timeline, [{"reason": "FailedScheduling"}])

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_names = list(context.get("objects", {}).get("node", {}).keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="AFFINITY_UNSATISFIABLE",
                    message="Pod affinity/anti-affinity rules cannot be satisfied on available nodes",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod scheduling blocked due to unsatisfiable affinity/anti-affinity",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.spec.affinity detected",
                "FailedScheduling events in timeline",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Affinity/anti-affinity constraints unsatisfiable"],
                **{
                    f"node:{n}": ["Node cannot satisfy pod affinity rules"]
                    for n in node_names
                },
            },
            "likely_causes": [
                "Affinity labels do not match any node",
                "Anti-affinity conflicts with existing pods",
                "Cluster topology insufficient to satisfy constraints",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review pod.spec.affinity and cluster node labels",
                "Check other pods that might block anti-affinity rules",
            ],
        }
