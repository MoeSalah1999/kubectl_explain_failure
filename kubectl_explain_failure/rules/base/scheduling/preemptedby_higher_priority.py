from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptedByHigherPriorityRule(FailureRule):
    """
    Detects Pod eviction due to scheduler preemption by a higher-priority Pod.

    Signals:
    - Pod.status.reason == "Preempted"
    - Scheduler has evicted the Pod to admit a higher-priority workload

    Interpretation:
    A higher-priority Pod required scheduling onto a node lacking sufficient 
    free resources. The scheduler invoked preemption logic and selected this 
    lower-priority Pod as a victim. The Pod was terminated and marked as 
    Preempted, preventing continued execution.

    Scope:
    - Scheduler phase
    - Deterministic (status-based)
    - Captures priority-based eviction decisions

    Exclusions:
    - Does not include voluntary Pod deletion
    - Does not include node drain or disruption eviction
    - Does not include resource insufficiency without preemption
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
                    code="HIGHER_PRIORITY_POD_PRESENT",
                    message="A higher-priority Pod required scheduling",
                    role="workload_context",
                ),
                Cause(
                    code="INSUFFICIENT_NODE_CAPACITY",
                    message="Target node lacked sufficient free resources for both Pods",
                    role="infrastructure_condition",
                ),
                Cause(
                    code="SCHEDULER_PREEMPTION_TRIGGERED",
                    message="Scheduler selected lower-priority Pods for eviction",
                    role="scheduler_decision",
                ),
                Cause(
                    code="POD_EVICTED_PREEMPTION",
                    message="Pod was evicted and marked as Preempted",
                    blocking=True,
                    role="scheduler_symptom",
                ),
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
                    "Scheduler evicted Pod due to higher-priority workload",
                ]
            },
            "likely_causes": [
                "Cluster resource pressure",
                "Higher-priority Pod scheduled onto the same node",
                "PreemptionPolicy allows eviction",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check PriorityClass configuration",
                "Review node capacity and resource pressure",
            ],
        }
