from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SchedulerPreemptionLoopRule(FailureRule):
    """
    Detects Pods stuck in repeated scheduler preemption attempts without
    progress, when no more specific blocker like PDB, affinity, or topology
    explains the failure.

    Real-world interpretation:
    - Scheduler repeatedly evaluates the Pod
    - Preemption is attempted or considered
    - The Pod remains Pending through multiple retries
    - Messages indicate generic preemption churn rather than a concrete,
      more specific root cause
    """

    name = "SchedulerPreemptionLoop"
    category = "Compound"
    priority = 85
    blocks = [
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

    SPECIFIC_BLOCKER_MARKERS = (
        "poddisruptionbudget",
        "would violate",
        "cannot evict pod",
        "didn't match pod affinity",
        "didn't match pod anti-affinity rules",
        "node affinity",
        "topology spread",
        "topology spread constraints",
        "volume node affinity conflict",
    )

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

            if any(marker in message for marker in self.SPECIFIC_BLOCKER_MARKERS):
                return False

            if any(marker in message for marker in self.PREEMPTION_MARKERS):
                preemption_hits += occurrences

        if preemption_hits < 3:
            return False
        if total_failures < 4:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < 60 and not repeated_signal:
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
                    code="SCHEDULER_PREEMPTION_THRASHING",
                    message="Scheduler repeatedly retries preemption without achieving a feasible placement",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_RETRY_LOOP",
                    message="Preemption attempts repeat without converging on a schedulable node",
                    role="control_loop",
                ),
                Cause(
                    code="POD_STARVATION",
                    message="Pod remains Pending due to repeated unsuccessful scheduling retries",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod is stuck in a scheduler preemption loop without a feasible placement",
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
                "Cluster capacity remains too constrained for the pod even after preemption attempts",
                "Preemption candidates do not free a usable node shape",
                "Higher-priority workload pressure keeps the scheduler retrying without progress",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe nodes",
                "Inspect scheduler logs for repeated preemption retries",
                "Evaluate resource requests versus current node capacity",
                "Check whether a more specific blocker such as PDB or affinity is present",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling with generic preemption retry behavior"
                ]
            },
        }
