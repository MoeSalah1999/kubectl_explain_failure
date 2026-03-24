from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class UnschedulableDueToPDBRule(FailureRule):
    """
    Detects Pending Pods that remain unschedulable because the scheduler
    cannot preempt protected Pods without violating a PodDisruptionBudget.

    Real-world interpretation:
    - The scheduler attempts preemption to place the Pod
    - Candidate victims are protected by a PDB
    - Scheduling keeps failing over time
    - The Pod remains Pending despite preemption attempts
    """

    name = "UnschedulableDueToPDB"
    category = "Compound"
    priority = 90
    deterministic = True
    blocks = [
        "SchedulerPreemptionLoop",
        "PreemptionIneffectiveDueToPDB",
        "InsufficientResources",
        "PodUnschedulable",
        "PriorityPreemptionChain",
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
        "would violate the poddisruptionbudget",
        "would violate poddisruptionbudget",
        "would violate the pdb",
        "cannot evict pod as it would violate",
        "cannot evict pod",
        "disruption budget",
    )

    MIN_TOTAL_FAILURES = 5
    MIN_DURATION_SECONDS = 90

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _source_component(self, event) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        recent_failures = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent_failures:
            return False

        pdb_hits = 0
        preemption_hits = 0
        total_failures = 0
        repeated_signal = False

        for event in recent_failures:
            message = str(event.get("message", "")).lower()
            source = self._source_component(event)
            occurrences = self._occurrences(event)

            if source and "scheduler" not in source:
                continue

            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            if any(marker in message for marker in self.PREEMPTION_MARKERS):
                preemption_hits += occurrences
            if any(marker in message for marker in self.PDB_MARKERS):
                pdb_hits += occurrences

        if preemption_hits < 2:
            return False
        if pdb_hits < 2:
            return False
        if total_failures < self.MIN_TOTAL_FAILURES:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < self.MIN_DURATION_SECONDS and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        dominant_msg = None
        if timeline:
            messages = [
                str(event.get("message", ""))
                for event in timeline.events_within_window(
                    15, reason="FailedScheduling"
                )
                if event.get("message")
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

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
                    message="Scheduler cannot preempt Pods because doing so would violate a PodDisruptionBudget",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_RETRY_LOOP",
                    message="Scheduler repeatedly retries placement but remains blocked by PDB protections",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains unscheduled due to PodDisruptionBudget constraints",
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
                "Scheduler messages explicitly indicate PodDisruptionBudget-protected victims",
                "Preemption attempts fail due to policy restrictions",
                "Sustained scheduling failure (>90s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "PodDisruptionBudget is too restrictive for current replica count",
                "All feasible victim Pods are protected by a PodDisruptionBudget",
                "Cluster capacity is tight enough that placement depends on evicting protected workloads",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pdb -o wide",
                "kubectl describe pdb",
                "Check minAvailable and maxUnavailable values",
                "Inspect replica counts of workloads protected by the PDB",
                "Consider whether the PDB is stricter than current cluster capacity can support",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Scheduling is blocked because preemption would violate a PodDisruptionBudget"
                ]
            },
        }
