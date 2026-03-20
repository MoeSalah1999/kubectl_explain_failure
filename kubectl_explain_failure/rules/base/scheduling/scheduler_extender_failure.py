from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SchedulerExtenderFailureRule(FailureRule):
    """
    Detects pod scheduling failures caused by an external scheduler extender
    rejecting pods or returning errors.

    Signals:
    - FailedScheduling events
    - Messages indicating scheduler extender rejection

    Scope:
    - Advanced scheduler integration
    - Deterministic
    """

    name = "SchedulerExtenderFailure"
    category = "Scheduling"
    priority = 25
    deterministic = True
    blocks = []
    requires = {"pod": True, "context": ["timeline"]}
    phases = ["Pending"]

    EXTENDER_MARKERS = (
        "scheduler extender rejected",
        "scheduler extender failed",
        "unable to schedule pod via extender",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        for e in timeline.raw_events:
            if e.get("reason") != "FailedScheduling":
                continue
            msg = (e.get("message") or "").lower()
            if any(marker in msg for marker in self.EXTENDER_MARKERS):
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        chain = CausalChain(
            causes=[
                Cause(
                    code="EXTENDER_REJECTION",
                    message="External scheduler extender rejected the Pod",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_BLOCKED_BY_EXTENDER",
                    message="Scheduler cannot place Pod due to extender rejection",
                    role="scheduling_symptom",
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_EXTENDER",
                    message="Pod remains unscheduled due to scheduler extender failure",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = ["Scheduler logs indicate extender rejection"]

        return {
            "rule": self.name,
            "root_cause": "Scheduler extender prevented pod scheduling",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {f"pod:{pod_name}": ["Rejected by scheduler extender"]},
            "likely_causes": [
                "Extender configured incorrectly",
                "Extender policy rejects pods due to custom constraints",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check scheduler extender logs",
                "Verify extender policies",
            ],
        }
