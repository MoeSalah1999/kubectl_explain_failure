from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class UnschedulableDueToPDBRule(FailureRule):
    """
    Detects Pods that cannot be scheduled because PodDisruptionBudgets (PDBs)
    prevent preemption from freeing capacity.

    Real-world behavior:
    - Scheduler attempts preemption to place Pod
    - Victim Pods are protected by PDBs
    - Preemption fails → scheduling fails repeatedly
    - Pod remains Pending despite available theoretical capacity

    Signals:
    - Repeated FailedScheduling events
    - Messages referencing PDB or inability to preempt
    - Sustained failure duration
    - No successful scheduling

    Distinction:
    - Stronger than generic preemption failure
    - Explicitly tied to PDB constraints
    """

    name = "UnschedulableDueToPDB"
    category = "Compound"
    priority = 90
    blocks = [
        "SchedulerPreemptionLoop",
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

        # --- 1. Repeated FailedScheduling events in short window ---
        recent_failures = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent_failures) < 4:
            return False

        # --- 2. Detect explicit PDB / preemption-blocked signals ---
        pdb_signals = 0

        for e in recent_failures:
            msg = (e.get("message") or "").lower()

            if (
                "poddisruptionbudget" in msg
                or "pdb" in msg
                or ("preempt" in msg and "not" in msg and "help" in msg)
                or "cannot evict" in msg
                or "would violate" in msg
            ):
                pdb_signals += 1

        if pdb_signals < 2:
            return False

        # --- 3. Sustained duration (avoid transient scheduler noise) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 45:
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant failure message
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
                    code="PDB_CONSTRAINT",
                    message="PodDisruptionBudget constraints prevent eviction of existing Pods",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_BLOCKED_BY_PDB",
                    message="Scheduler cannot preempt Pods due to PDB protection",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULING_ATTEMPTS_FAIL",
                    message="Scheduler repeatedly fails to find feasible node",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains unscheduled due to PDB constraints",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod cannot be scheduled because PodDisruptionBudgets prevent preemption",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events detected",
                "Scheduler messages indicate PDB or eviction constraints",
                "Preemption attempts fail due to policy restrictions",
                "Sustained scheduling failure (>45s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "PodDisruptionBudget too restrictive (minAvailable too high)",
                "All candidate victim Pods are protected by PDBs",
                "Cluster operating near capacity with strict availability guarantees",
                "Workload replicas insufficient to allow disruption",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pdb",
                "kubectl describe pdb",
                "kubectl get events --sort-by=.lastTimestamp",
                "Check minAvailable / maxUnavailable in PDBs",
                "Evaluate whether PDB constraints are overly strict",
                "Inspect replica counts for protected workloads",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Scheduling blocked by PodDisruptionBudget constraints"
                ]
            },
        }
