from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptionIneffectiveDueToTopologySpreadRule(FailureRule):
    """
    Detects scheduling failures where:

    - Scheduler attempts preemption
    - BUT topologySpreadConstraints prevent placement even after preemption
    - Result: preemption is ineffective, pod remains Pending

    Real-world interpretation:
    - Topology constraints (zone/node/hostname spread) are too strict
    - Even evicting lower-priority pods cannot create a valid placement
    - Scheduler reports "preemption not helpful" or similar

    Signals:
    - FailedScheduling events mentioning BOTH:
        - preemption
        - topology spread constraint violations
    - Repeated failures within a short window
    - No successful scheduling
    - Sustained duration (not transient)

    Scope:
    - Scheduler constraint failure (topology-aware)
    - More specific than generic preemption loop

    Exclusions:
    - Generic resource shortage (handled elsewhere)
    - Pure topology mismatch without preemption
    """

    name = "PreemptionIneffectiveDueToTopologySpread"
    category = "Scheduling"
    priority = 90  # higher than generic preemption loop
    blocks = [
        "SchedulerPreemptionLoop",
        "PodTopologySpreadUnsatisfiable",
        "InsufficientResources",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Recent FailedScheduling events ---
        recent = timeline.events_within_window(
            5,
            reason="FailedScheduling",
        )

        if len(recent) < 3:
            return False

        # --- 2. Detect combined signal: preemption + topology spread ---
        matched_events = 0

        for e in recent:
            msg = (e.get("message") or "").lower()

            has_preemption = (
                "preempt" in msg or "preemption" in msg or "not helpful" in msg
            )

            has_topology = (
                "topology spread" in msg
                or "didn't match pod topology spread constraints" in msg
                or "cannot satisfy topology spread" in msg
            )

            if has_preemption and has_topology:
                matched_events += 1

        if matched_events < 2:
            return False

        # --- 3. Sustained failure duration ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 45:  # shorter threshold than loop rule (more specific signal)
            return False

        # --- 4. Ensure no successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant message for evidence
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(5, reason="FailedScheduling")
                if e.get("message")
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_CONSTRAINT",
                    message="Topology spread constraints restrict valid node placement",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_INEFFECTIVE",
                    message="Preemption cannot create a placement that satisfies topology constraints",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler rejects all nodes due to unsatisfiable constraints",
                    role="scheduling_decision",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending due to unsatisfiable topology constraints",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Preemption is ineffective because topology spread constraints cannot be satisfied",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "FailedScheduling events include both preemption attempts and topology spread constraint violations",
                "Multiple scheduling retries within short window",
                "Scheduler indicates preemption is not helpful",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Topology spread constraints are too strict for current cluster state",
                "Insufficient nodes across required topology domains (zones/hosts)",
                "Uneven pod distribution preventing rebalancing",
                "Node labels do not match topology keys",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check topologySpreadConstraints in pod spec",
                "Verify topologyKey labels exist on nodes",
                "Evaluate maxSkew and whenUnsatisfiable settings",
                "Check distribution of existing pods across topology domains",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Topology spread constraints prevent scheduling even with preemption"
                ]
            },
        }
