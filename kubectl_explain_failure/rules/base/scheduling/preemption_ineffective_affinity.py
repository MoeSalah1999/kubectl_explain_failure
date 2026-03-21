from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptionIneffectiveDueToAffinityRule(FailureRule):
    """
    Detects scheduler failures where preemption is attempted but
    cannot succeed due to affinity / anti-affinity constraints.

    Real-world interpretation:
    - Scheduler considers preemption
    - But evicting Pods does NOT make the node eligible
    - Because:
        * PodAffinity rules cannot be satisfied
        * PodAntiAffinity rules block placement
        * NodeAffinity restricts viable nodes
    - Result: "preemption is not helpful" scenarios

    Signals:
    - FailedScheduling events with preemption-related messages
    - Messages indicating "preemption is not helpful"
    - Presence of affinity / anti-affinity semantics in failure message
    - Repeated failures (not transient)
    - No successful scheduling

    Key distinction:
    - Unlike generic preemption loop:
        THIS rule identifies structural unsatisfiability
        caused by affinity constraints, not just resource pressure.
    """

    name = "PreemptionIneffectiveDueToAffinity"
    category = "Scheduling"
    priority = 80

    blocks = [
        "PodUnschedulable",
        "InsufficientResources",
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

        # --- 1. Repeated FailedScheduling events ---
        recent = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent) < 3:
            return False

        # --- 2. Detect preemption attempts ---
        preemption_hits = 0
        affinity_hits = 0

        for e in recent:
            msg = (e.get("message") or "").lower()

            # Preemption signal
            if "preempt" in msg:
                preemption_hits += 1

            # Affinity / anti-affinity / node affinity signals
            if any(
                keyword in msg
                for keyword in [
                    "affinity",
                    "anti-affinity",
                    "node affinity",
                    "didn't match pod affinity",
                    "didn't satisfy existing pods anti-affinity",
                ]
            ):
                affinity_hits += 1

            # Strong canonical signal (K8s scheduler message)
            if "preemption is not helpful" in msg:
                preemption_hits += 2  # strong weight
                affinity_hits += 2

        if preemption_hits < 2:
            return False

        if affinity_hits < 2:
            return False

        # --- 3. Sustained duration (not a transient blip) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 30:
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

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
                    code="AFFINITY_CONSTRAINT_CONFLICT",
                    message="Pod affinity/anti-affinity rules restrict eligible nodes",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_INEFFECTIVE",
                    message="Preemption cannot create a schedulable placement due to constraints",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler rejects all nodes even after considering preemption",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_UNSCHEDULABLE",
                    message="Pod remains Pending due to unsatisfiable affinity constraints",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Preemption is ineffective because affinity or anti-affinity constraints prevent scheduling",
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events detected",
                "Scheduler attempted preemption but could not find a valid placement",
                "Affinity or anti-affinity constraints present in scheduling failures",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "PodAffinity rules cannot be satisfied by any node",
                "PodAntiAffinity rules exclude all candidate nodes",
                "NodeAffinity restricts scheduling to unavailable nodes",
                "Cluster topology does not satisfy placement constraints",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "Inspect pod.spec.affinity rules",
                "Check node labels against nodeAffinity requirements",
                "Verify pod anti-affinity is not over-constraining placement",
                "Temporarily relax affinity rules to confirm root cause",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Scheduler preemption attempts failed due to affinity constraints"
                ]
            },
        }
