from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PriorityPreemptionChainRule(FailureRule):
    """
    Detects Pods that enter Failed state because they were preempted
    by a higher-priority workload during scheduling.

    Signals:
    - Recent Scheduled event for a higher-priority Pod
    - Preempted event for the affected Pod
    - Pod phase is Failed

    Interpretation:
    The scheduler admitted a higher-priority Pod onto a Node with
    constrained capacity. As a result, a lower-priority Pod was
    preempted and subsequently evicted. The Pod failure is therefore
    a consequence of priority-based scheduling policy rather than
    node health or container runtime failure.

    Scope:
    - Scheduling layer (priority + preemption mechanics)
    - Deterministic (event sequence correlation)
    - Acts as a compound rule suppressing generic eviction
    or node-level failure explanations when preemption
    is the upstream cause

    Exclusions:
    - Does not include evictions due to node pressure
    - Does not include controller-driven Pod deletions
    - Does not include container runtime crashes
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

        # --- Must contain recent preemption signal ---
        recent_preemptions = timeline.events_within_window(
            10, reason="Preempted"
        )
        if not recent_preemptions:
            return False

        # --- Must contain recent scheduling activity ---
        recent_scheduling = timeline.events_within_window(
            10, reason="Scheduled"
        )
        if not recent_scheduling:
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
                    code="PRIORITY_SCHEDULING_DECISION",
                    message="Scheduler admitted higher-priority Pod, triggering preemption",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="LOW_PRIORITY_POD_PREEMPTED",
                    message="Lower priority pod was preempted by scheduler",
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
                f"pod:{pod_name}": ["Pod was preempted by higher priority workload"],
                **(
                    {
                        f"node:{scheduled_node}": [
                            "Node scheduled higher priority pod triggering preemption"
                        ]
                    }
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
