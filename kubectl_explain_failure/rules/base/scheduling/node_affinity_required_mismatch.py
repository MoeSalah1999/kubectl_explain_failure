from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeAffinityRequiredMismatchRule(FailureRule):
    """
    Detects FailedScheduling caused by required NodeAffinity rules
    that do not match any available node.

    Signals:
    - FailedScheduling events
    - Message mentions 'node affinity'

    Scope:
    - Node scheduling constraints
    - Deterministic
    """

    name = "NodeAffinityRequiredMismatch"
    category = "Scheduling"
    priority = 28
    deterministic = True
    blocks = []
    requires = {"pod": True, "context": ["timeline", "objects"]}
    phases = ["Pending"]

    NODE_AFFINITY_MARKERS = (
        "node(s) didn't match node affinity",
        "node affinity mismatch",
        "no nodes available for pod",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            if e.get("reason") != "FailedScheduling":
                continue
            msg = (e.get("message") or "").lower()
            if any(marker in msg for marker in self.NODE_AFFINITY_MARKERS):
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_AFFINITY_CONFLICT",
                    message="Pod requires node labels not present on any node",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_NODE_AFFINITY",
                    message="Scheduler cannot place pod due to node affinity mismatch",
                    role="scheduling_symptom",
                ),
                Cause(
                    code="WORKLOAD_PLACEMENT_BLOCKED",
                    message="Pod cannot be scheduled on any available node",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = ["Scheduler reports node affinity conflict"]

        return {
            "rule": self.name,
            "root_cause": "Required node affinity prevents scheduling",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": ["Required node labels not present"]
            },
            "likely_causes": [
                "PodSpec specifies required NodeAffinity labels not present on any node",
                "Cluster nodes missing requested labels",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check Pod.spec.affinity.nodeAffinity.requiredDuringScheduling",
            ],
        }
