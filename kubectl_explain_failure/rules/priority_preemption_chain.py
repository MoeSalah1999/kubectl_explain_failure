from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PriorityPreemptionChainRule(FailureRule):
    """
    High-priority pod scheduled
    → Lower-priority pod preempted
    → Pod evicted
    """

    name = "PriorityPreemptionChain"
    category = "Compound"
    priority = 60
    blocks = [
        "PreemptedByHigherPriority",
        "NodeNotReadyEvicted",
    ]
    phases = ["Failed"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Must contain preemption signal
        if not timeline_has_pattern(timeline, "Preempted"):
            return False

        # Must contain scheduling activity
        if not timeline.has(kind="Scheduling"):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        # Try to extract node from scheduling event (best effort, deterministic)
        scheduled_node = "<unknown>"
        timeline = context.get("timeline")
        if timeline:
            for e in timeline.raw_events:
                if e.get("reason") == "Scheduled":
                    msg = e.get("message", "")
                    # Typical message: "Successfully assigned ns/pod to node-x"
                    if " to " in msg:
                        scheduled_node = msg.split(" to ")[-1].strip()
                        break

        chain = CausalChain(
            causes=[
                Cause(
                    code="HIGH_PRIORITY_POD_SCHEDULED",
                    message="Higher priority pod scheduled on node",
                    blocking=True,
                    role="scheduler_root",
                ),
                Cause(
                    code="LOW_PRIORITY_POD_PREEMPTED",
                    message="Lower priority pod was preempted",
                    blocking=True,
                    role="scheduler_intermediate",
                ),
                Cause(
                    code="POD_EVICTED",
                    message="Pod evicted due to priority preemption",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod was evicted due to higher-priority workload preemption",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Preemption event detected",
                "Scheduling activity for higher priority pod",
                "Pod phase is Failed",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod was preempted by higher priority workload"
                ],
                **(
                    {f"node:{scheduled_node}": [
                        "Node scheduled higher priority pod triggering preemption"
                    ]}
                    if scheduled_node != "<unknown>"
                    else {}
                ),
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect PriorityClass configuration",
                "Evaluate node resource pressure",
                "Consider increasing pod priority if appropriate",
            ],
            "blocking": True,
        }
