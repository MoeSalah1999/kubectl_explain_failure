from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class TopologySpreadUnsatisfiableRule(FailureRule):
    """
    Detects Pod scheduling failures caused by unsatisfiable topologySpreadConstraints.

    Signals:
    - Pod.spec.topologySpreadConstraints is defined
    - Timeline contains 'FailedScheduling' events
    - Scheduler reports inability to satisfy topology skew requirements

    Interpretation:
    The Pod declares topology spread constraints requiring balanced 
    distribution across topology domains (e.g., zones or nodes). 
    The scheduler cannot find a placement that satisfies maxSkew and 
    topologyKey rules given the current cluster state, leaving the Pod 
    in a Pending state.

    Scope:
    - Scheduler phase
    - Deterministic (object + event based)
    - Captures hard topology constraint violations

    Exclusions:
    - Does not include resource insufficiency failures
    - Does not include nodeSelector or node affinity mismatches
    - Does not include priority-based preemption
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

        tsc = pod.get("spec", {}).get("topologySpreadConstraints", [])

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_TOPOLOGY_CONSTRAINTS_DEFINED",
                    message=f"Pod declares topologySpreadConstraints: {tsc}",
                    role="workload_context",
                ),
                Cause(
                    code="TOPOLOGY_CONSTRAINTS_UNSATISFIABLE",
                    message="Scheduler found no feasible node placement satisfying maxSkew and topologyKey rules",
                    role="infrastructure_root",
                ),
                Cause(
                    code="POD_SCHEDULING_FAILED_TOPOLOGY",
                    message="Pod remains Pending due to unsatisfiable topology spread constraints",
                    blocking=True,
                    role="scheduler_symptom",
                ),
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
                "FailedScheduling events in timeline",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["TopologySpreadConstraints unsatisfiable"],
                **{
                    f"node:{n}": ["Node cannot satisfy topology spread constraints"]
                    for n in node_names
                },
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
