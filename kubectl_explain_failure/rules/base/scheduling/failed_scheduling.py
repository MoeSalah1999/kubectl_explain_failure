from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class FailedSchedulingRule(FailureRule):
    """
    Scheduler cannot place Pod
    → Pod remains Pending
    """

    name = "FailedScheduling"
    category = "Scheduling"
    priority = 16
    blocks = []
    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # If specific scheduling causes detected, do NOT match
        specific_patterns = [
            "insufficient",
            "affinity",
            "topology",
            "hostport",
            "taint",
        ]
        messages = [e.get("message", "").lower() for e in timeline.raw_events]
        if any(any(p in msg for p in specific_patterns) for msg in messages):
            return False

        return any(
            "failedscheduling" in e.get("reason", "").lower()
            for e in timeline.raw_events
        )

    def explain(self, pod, events, context):
        pod_name = pod["metadata"]["name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler could not place Pod on any node",
                    blocking=True,
                    role="scheduling_root",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains in Pending phase",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Scheduler could not place Pod on any node",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Events contain FailedScheduling from default-scheduler",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Scheduler emitted FailedScheduling event"]
            },
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get nodes -o wide",
                "kubectl describe node <node>",
            ],
        }
