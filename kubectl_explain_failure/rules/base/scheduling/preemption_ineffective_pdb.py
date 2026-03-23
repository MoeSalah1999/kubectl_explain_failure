from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptionIneffectiveDueToPDBRule(FailureRule):
    """
    Detects scheduling failures where preemption is attempted
    but consistently blocked due to PodDisruptionBudget (PDB) constraints.

    Real-world interpretation:
    - Scheduler attempts preemption to free capacity
    - Candidate Pods cannot be evicted due to PDB guarantees
    - Scheduling repeatedly fails despite preemption attempts

    This is NOT a generic unschedulable condition — it is a
    *specific preemption failure mode*.

    Signals:
    - FailedScheduling events containing BOTH:
        - preemption attempts
        - PDB violation / eviction denial semantics
    - Repeated occurrences within a time window
    - No successful scheduling

    Scope:
    - Scheduling layer (preemption mechanics)
    - Non-compound root cause (feeds into compound loop rules)
    - High specificity, near-deterministic when message is present

    Exclusions:
    - Pure resource insufficiency without PDB involvement
    - Successful preemption (handled by PriorityPreemptionChain)
    """

    name = "PreemptionIneffectiveDueToPDB"
    category = "Scheduling"
    priority = 75

    blocks = [
        "InsufficientResources",
        "PodUnschedulable",
        "FailedScheduling",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    PREEMPTION_MARKERS = (
        "preemption:",
        "preemption is not helpful",
        "no preemption victims found for incoming pod",
        "preempt",
    )

    PDB_MARKERS = (
        "poddisruptionbudget",
        "disruption budget",
        "cannot evict pod",
        "would violate",
        "violating pdb",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Recent FailedScheduling events ---
        recent_failures = timeline.events_within_window(15, reason="FailedScheduling")

        if not recent_failures:
            return False

        # --- 2. Detect PDB-blocked preemption semantics ---
        pdb_blocked = 0
        preemption_present = 0
        total_failures = 0
        repeated_signal = False

        for e in recent_failures:
            msg = (e.get("message") or "").lower()
            occurrences = self._occurrences(e)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            # preemption attempt signal
            if any(marker in msg for marker in self.PREEMPTION_MARKERS):
                preemption_present += occurrences

            # PDB / eviction denial signals (real kube messages)
            if any(marker in msg for marker in self.PDB_MARKERS):
                pdb_blocked += occurrences

        # Must have BOTH signals
        if preemption_present < 2:
            return False

        if pdb_blocked < 2:
            return False

        if total_failures < 3:
            return False

        # --- 3. Ensure failure is not transient ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 30 and not repeated_signal:
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        timeline = context.get("timeline")

        # Extract representative failure message
        representative_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(15, reason="FailedScheduling")
                if any(marker in (e.get("message") or "").lower() for marker in self.PDB_MARKERS)
            ]
            if msgs:
                representative_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="PDB_CONSTRAINT_ENFORCED",
                    message="PodDisruptionBudget prevents eviction of candidate pods",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_BLOCKED",
                    message="Scheduler preemption attempts are blocked by PDB constraints",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULING_FAILURE",
                    message="Pod cannot be scheduled despite preemption attempts",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Scheduler preemption is ineffective due to PodDisruptionBudget constraints",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                "FailedScheduling events indicate preemption attempts",
                "Eviction blocked due to PodDisruptionBudget",
                "Repeated scheduling failures without progress",
                "No successful scheduling observed",
                *(
                    ["Representative scheduler message: " + representative_msg]
                    if representative_msg
                    else []
                ),
            ],
            "likely_causes": [
                "PodDisruptionBudget too restrictive (minAvailable / maxUnavailable)",
                "Too few replicas to allow safe eviction",
                "High-priority pod cannot displace protected workloads",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pdb -o wide",
                "kubectl describe pdb",
                "Evaluate minAvailable / maxUnavailable settings",
                "Check replica counts of protected workloads",
                "Consider relaxing PDB constraints if appropriate",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Preemption attempts blocked by PodDisruptionBudget"
                ]
            },
        }
