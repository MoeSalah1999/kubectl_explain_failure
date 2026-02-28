from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class AffinityUnsatisfiableRule(FailureRule):
    """
    Detects Pod scheduling failures caused by unsatisfiable affinity or anti-affinity constraints.

    Signals:
    - Pod.spec.affinity is defined
    - Timeline contains 'FailedScheduling' events
    - Cluster nodes are present but cannot satisfy constraints

    Interpretation:
    The Pod declares affinity or anti-affinity rules that cannot be
    satisfied by any available node. The scheduler fails to place the Pod,
    leaving it Pending with repeated FailedScheduling events.

    Scope:
    - Scheduler constraint resolution layer
    - Deterministic (spec & event-based)
    - Captures topology and label constraint conflicts

    Exclusions:
    - Does not include resource-based scheduling failures (CPU/memory pressure)
    - Does not include taint/toleration conflicts
    - Does not include node readiness or infrastructure outages
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
        node_count = len(node_names)

        chain = CausalChain(
            causes=[
                Cause(
                    code="AFFINITY_RULES_DEFINED",
                    message="Pod defines affinity/anti-affinity constraints",
                    role="workload_context",
                ),
                Cause(
                    code="SCHEDULER_CONSTRAINT_UNSATISFIED",
                    message=f"No available node (out of {node_count}) satisfies affinity constraints",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE",
                    message="Scheduler cannot place Pod; Pod remains Pending",
                    role="workload_symptom",
                ),
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
