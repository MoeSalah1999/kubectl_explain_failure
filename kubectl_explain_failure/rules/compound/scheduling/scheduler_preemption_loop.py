from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SchedulerPreemptionLoopRule(FailureRule):
    """
    Detects Pods stuck in a scheduler preemption loop where:

    - The Pod is repeatedly considered for scheduling
    - The scheduler attempts preemption but fails to make progress
    - The Pod remains Pending due to starvation

    Real-world interpretation:
    This occurs when:
    - Cluster is resource-constrained
    - Preemption candidates are insufficient or protected (PDBs)
    - Higher-priority Pods continuously block placement
    - Scheduler repeatedly retries without convergence

    Signals:
    - Repeated FailedScheduling events (with preemption hints)
    - High frequency within short time window
    - Sustained duration (scheduler retry loop)
    - No successful Scheduled event

    Scope:
    - Scheduler behavior (preemption + retry loop)
    - Compound rule (captures systemic scheduling failure)
    - Non-deterministic but high confidence when sustained

    Exclusions:
    - Single scheduling failure (covered by simpler rules)
    - Immediate preemption success (handled by PriorityPreemptionChain)
    """

    name = "SchedulerPreemptionLoop"
    category = "Compound"
    priority = 85
    blocks = [
        "InsufficientResources",
        "PodUnschedulable",
        "PriorityPreemptionChain",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Repeated FailedScheduling in short window ---
        recent_failures = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent_failures) < 5:
            return False

        # --- 2. Ensure failures contain preemption semantics ---
        preemption_signals = 0
        for e in recent_failures:
            msg = (e.get("message") or "").lower()
            if "preempt" in msg:
                preemption_signals += 1

        if preemption_signals < 3:
            return False

        # --- 3. Sustained retry loop (duration check) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 60:  # less than 1 minute → too transient
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        timeline = context.get("timeline")

        # Extract dominant failure message (best-effort signal)
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(5, reason="FailedScheduling")
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_RESOURCE_CONTENTION",
                    message="Cluster resources insufficient for stable scheduling",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_INSUFFICIENT",
                    message="Scheduler preemption attempts cannot free suitable capacity",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_RETRY_LOOP",
                    message="Scheduler repeatedly retries scheduling without convergence",
                    role="control_loop",
                ),
                Cause(
                    code="POD_STARVATION",
                    message="Pod remains Pending due to continuous scheduling failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod is stuck in a scheduler preemption loop due to resource contention",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events within short time window",
                "Preemption attempts detected in scheduler messages",
                "Sustained scheduling retry duration (>60s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Insufficient cluster capacity for requested resources",
                "PodDisruptionBudgets preventing effective preemption",
                "High-priority workloads continuously occupying resources",
                "Fragmented resources preventing bin-packing",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe nodes",
                "Check PodDisruptionBudgets (kubectl get pdb)",
                "Evaluate resource requests vs cluster capacity",
                "Inspect PriorityClass usage across workloads",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling with preemption attempts"
                ]
            },
        }
