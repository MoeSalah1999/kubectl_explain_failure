from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SchedulingFlappingRule(FailureRule):
    """
    Detects Pods that repeatedly alternate between Scheduled and
    FailedScheduling events within a short duration, indicating
    scheduling instability.

    Signals:
    - Alternating Scheduled and FailedScheduling events
    - Multiple scheduling transitions within a bounded time window
    - Pod phase remains Pending

    Interpretation:
    The scheduler repeatedly attempts to place the Pod but alternates
    between successful and failed placement decisions. This behavior
    indicates fluctuating cluster feasibility conditions such as
    resource contention or rapid node state changes, resulting in
    unstable scheduling outcomes.

    Scope:
    - Scheduling layer (scheduler decision stability)
    - Deterministic (event pattern correlation within bounded window)
    - Acts as a compound rule suppressing simple FailedScheduling
    explanations when instability is the upstream cause

    Exclusions:
    - Does not include single scheduling failures
    - Does not include PVC or controller blocking conditions
    - Does not include post-scheduling container runtime failures
    """

    name = "SchedulingFlapping"
    category = "Compound"
    priority = 57  # Below PVC escalation but above simple scheduling rules
    blocks = [
        "FailedScheduling",
        "InsufficientResources",
        "NodeSelectorMismatch",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    MIN_ALTERNATIONS = 3
    MAX_DURATION_SECONDS = 300  # 5 minutes instability window

    def matches(self, pod, events, context) -> bool:
        timeline: Timeline = context.get("timeline")
        if not timeline:
            return False

        # Only look at recent scheduling activity
        recent = timeline.events_within_window(
            self.MAX_DURATION_SECONDS // 60
        )

        scheduling_events = [
            e for e in recent
            if e.get("reason") in ("Scheduled", "FailedScheduling")
        ]

        if len(scheduling_events) < self.MIN_ALTERNATIONS:
            return False

        reasons = {e.get("reason") for e in scheduling_events}
        if not {"Scheduled", "FailedScheduling"}.issubset(reasons):
            return False

        # Duration check remains global but still deterministic
        duration = timeline.duration_between(
            lambda e: e.get("reason") in ("Scheduled", "FailedScheduling")
        )

        if duration == 0 or duration > self.MAX_DURATION_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_INSTABILITY",
                    message="Scheduler repeatedly alternated between success and failure",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="REPEATED_SCHEDULING_ATTEMPTS",
                    message="Scheduler repeatedly attempted placement due to fluctuating feasibility",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING_UNSTABLE",
                    message="Pod remains Pending due to scheduling instability",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Cluster scheduling instability causing flapping",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Alternating Scheduled and FailedScheduling events detected",
                "Multiple scheduling transitions within short duration",
                "Cluster resource state appears unstable",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Repeated scheduling attempts observed"]
            },
            "suggested_checks": [
                "kubectl describe nodes",
                "Inspect cluster autoscaler activity",
                "Check for resource pressure conditions",
                "Review recent node additions/removals",
            ],
            "blocking": True,
        }
