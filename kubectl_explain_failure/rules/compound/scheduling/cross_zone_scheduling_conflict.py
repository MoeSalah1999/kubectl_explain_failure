from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CrossZoneSchedulingConflictRule(FailureRule):
    """
    Detects Pods that cannot be scheduled due to cross-zone / topology constraints.

    Real-world interpretation:
    - Pod has nodeAffinity / topologySpreadConstraints / anti-affinity
    - Required zone(s) lack capacity or compatible nodes
    - Scheduler repeatedly fails despite cluster having resources elsewhere

    Typical scheduler messages include:
    - "node(s) didn't match node affinity"
    - "didn't satisfy existing pods anti-affinity rules"
    - "topology spread constraints"
    - zone/region mismatch signals

    Signals:
    - Repeated FailedScheduling events
    - Zone / topology-related constraint messages
    - Sustained scheduling failure duration
    - No successful scheduling

    Scope:
    - Advanced scheduler placement constraints
    - Compound rule (multi-factor scheduling failure)
    """

    name = "CrossZoneSchedulingConflict"
    category = "Compound"
    priority = 82
    blocks = [
        "PodUnschedulable",
        "TopologySpreadUnsatisfiable",
        "NodeAffinityMismatch",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Repeated scheduling failures in short window ---
        recent_failures = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent_failures) < 4:
            return False

        # --- 2. Detect topology / zone-related constraint signals ---
        topology_signals = 0

        for e in recent_failures:
            msg = (e.get("message") or "").lower()

            if any(
                keyword in msg
                for keyword in [
                    "node affinity",
                    "didn't match node affinity",
                    "match node selector",
                    "topology spread",
                    "anti-affinity",
                    "zone",
                    "topology",
                ]
            ):
                topology_signals += 1

        if topology_signals < 3:
            return False

        # --- 3. Sustained failure duration ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 45:  # avoid transient imbalance
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant scheduler message for clarity
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
                    code="TOPOLOGY_CONSTRAINT_ENFORCED",
                    message="Pod enforces strict topology or zone placement constraints",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="ZONE_CAPACITY_OR_MATCH_FAILURE",
                    message="Required zone lacks capacity or compatible nodes",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_FILTER_EXCLUSION",
                    message="Scheduler filters out nodes due to affinity or topology constraints",
                    role="scheduling_decision",
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_IN_TARGET_ZONE",
                    message="Pod remains Pending due to unsatisfied cross-zone constraints",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod cannot be scheduled due to cross-zone or topology placement constraints",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events within short time window",
                "Scheduler messages indicate topology/zone constraint violations",
                "Sustained scheduling failure duration (>45s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Node affinity restricts Pod to unavailable zones",
                "Topology spread constraints cannot be satisfied",
                "Pod anti-affinity prevents placement in available zones",
                "Uneven resource distribution across zones",
                "Cluster capacity exists but not in required topology domain",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check node labels for topology.kubernetes.io/zone",
                "Review pod affinity/anti-affinity rules",
                "Inspect topologySpreadConstraints in pod spec",
                "Evaluate per-zone resource availability",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling due to topology/zone constraints"
                ]
            },
        }
