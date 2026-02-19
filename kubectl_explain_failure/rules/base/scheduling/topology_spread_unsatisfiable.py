from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class TopologySpreadUnsatisfiableRule(FailureRule):
    """
    Detects pod scheduling failures due to unsatisfiable topologySpreadConstraints.
    Triggered when Pod.spec.topologySpreadConstraints exist and scheduling failed.
    """
    name = "TopologySpreadUnsatisfiable"
    category = "Scheduling"
    priority = 21

    requires = {
        "context": ["timeline"],
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        tsc = pod.get("spec", {}).get("topologySpreadConstraints", [])
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})

        if not tsc or not timeline or not node_objs:
            return False

        # Check scheduling failure events
        return timeline_has_pattern(timeline, [{"reason": "FailedScheduling"}])

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_names = list(context.get("objects", {}).get("node", {}).keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_UNSATISFIABLE",
                    message="Pod topologySpreadConstraints cannot be satisfied on available nodes",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod scheduling blocked due to unsatisfiable topology spread constraints",
            "confidence": 0.94,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.spec.topologySpreadConstraints detected",
                "FailedScheduling events in timeline"
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["TopologySpreadConstraints unsatisfiable"],
                **{f"node:{n}": ["Node cannot satisfy topology spread constraints"] for n in node_names},
            },
            "likely_causes": [
                "Insufficient nodes to satisfy maxSkew and topology keys",
                "Node labels or zones misconfigured",
                "Other pods preventing balanced distribution",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check pod.spec.topologySpreadConstraints and node labels",
                "Verify cluster has sufficient nodes per topology domain",
            ],
        }