from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SchedulingTimeoutExceededRule(FailureRule):
    """
    Detects Pods that repeatedly fail scheduling for a prolonged period.

    Signals:
    - Multiple FailedScheduling events
    - Duration exceeds configured threshold (default: 10 minutes)

    Interpretation:
    The scheduler has repeatedly rejected the Pod, indicating potential
    cluster starvation, deadlock, or persistent scheduling constraints.

    Scope:
    - Temporal / cluster-level failure
    - Non-deterministic (depends on event history)
    """

    name = "SchedulingTimeoutExceeded"
    category = "Temporal"
    priority = 60
    deterministic = False
    blocks = []
    requires = {
        "context": ["timeline"]
    }

    # Configurable parameters
    failed_scheduling_reason = "FailedScheduling"
    min_repeats = 3
    duration_minutes = 10  # threshold for timeout

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Filter FailedScheduling events within duration
        recent_events = timeline.events_within_window(
            self.duration_minutes,
            reason=self.failed_scheduling_reason,
        )

        # Check if number of repeated events exceeds threshold
        return len(recent_events) >= self.min_repeats

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        recent_events = timeline.events_within_window(
            self.duration_minutes,
            reason=self.failed_scheduling_reason,
        )

        duration_seconds = 0
        if recent_events:
            first_ts = recent_events[0].get("firstTimestamp") or recent_events[0].get("lastTimestamp")
            last_ts = recent_events[-1].get("lastTimestamp") or recent_events[-1].get("firstTimestamp")
            if first_ts and last_ts:
                from kubectl_explain_failure.timeline import parse_time
                duration_seconds = (parse_time(last_ts) - parse_time(first_ts)).total_seconds()

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPEATED_FAILED_SCHEDULING",
                    message=f"Pod has failed scheduling {len(recent_events)} times",
                    role="temporal_context",
                ),
                Cause(
                    code="SCHEDULER_TIMEOUT_EXCEEDED",
                    message=f"FailedScheduling events persisted for {duration_seconds/60:.1f} minutes",
                    role="temporal_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_CLUSTER_STARVATION",
                    message="The Pod may be unschedulable due to cluster starvation or deadlock",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod repeatedly failed scheduling for prolonged duration",
            "confidence": 0.92,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"FailedScheduling events count: {len(recent_events)}",
                f"Duration: {duration_seconds/60:.1f} minutes",
            ],
            "object_evidence": {
                f"pod:{pod.get('metadata', {}).get('name', '<unknown>')}": [
                    f"{len(recent_events)} FailedScheduling events over {duration_seconds/60:.1f} minutes"
                ]
            },
            "likely_causes": [
                "Cluster nodes are fully utilized",
                "Unsatisfiable scheduling constraints (affinity/taints/resources)",
                "Pod scheduling deadlock or starvation",
            ],
            "suggested_checks": [
                "kubectl get nodes -o wide",
                "kubectl describe pod {0}".format(pod.get("metadata", {}).get("name", "<pod>")),
                "Check node resources, taints, and affinity constraints",
            ],
        }