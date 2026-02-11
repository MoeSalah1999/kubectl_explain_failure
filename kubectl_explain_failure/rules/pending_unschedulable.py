from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase, has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class PendingUnschedulableRule(FailureRule):
    name = "PendingUnschedulable"
    category = "Compound"
    priority = 55
    blocks = ["FailedScheduling"]
    requires = {"context": ["timeline"]}
    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        # Only match if pod is Pending and there is FailedScheduling
        blocking_pvc = context.get("blocking_pvc")
        if (
            get_pod_phase(pod) == "Pending"
            and has_event(events, "FailedScheduling")
            and (blocking_pvc is None)
        ):
            return True
        return False

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="FAILED_SCHEDULING",
                    message="Scheduler failed to place pod",
                    blocking=True,
                )
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        return {
            "root_cause": "Pod Pending due to FailedScheduling (unschedulable)",
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} remains Pending",
                "FailedScheduling event observed",
            ],
            "object_evidence": {f"pod:{pod_name}, phase:Pending": ["Unschedulable"]},
            "likely_causes": ["Node taints or insufficient resources"],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "Check resource requests and taints",
            ],
            "blocking": True,
        }
