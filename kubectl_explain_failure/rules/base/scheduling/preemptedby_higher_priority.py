from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptedByHigherPriorityRule(FailureRule):
    """
    Detects Pod preemption due to higher priority Pod.
    Triggered when Pod.status.reason = "Preempted".
    """

    name = "PreemptedByHigherPriority"
    category = "Scheduling"
    priority = 66

    requires = {
        "pod": True,
    }

    def matches(self, pod, events, context) -> bool:
        return pod.get("status", {}).get("reason") == "Preempted"

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_PREEMPTED",
                    message=f"Pod was preempted by a higher-priority Pod",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod was preempted by a higher-priority workload",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.status.reason=Preempted",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod.status.reason=Preempted",
                    "Scheduler evicted Pod due to higher-priority workload"
                ]
            },
            "likely_causes": [
                "Cluster resource pressure",
                "Higher-priority Pod scheduled onto the same node",
                "PreemptionPolicy allows eviction"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check PriorityClass configuration",
                "Review node capacity and resource pressure"
            ],
        }
