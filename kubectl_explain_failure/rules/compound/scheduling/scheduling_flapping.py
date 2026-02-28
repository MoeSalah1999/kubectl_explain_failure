from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SchedulingFlappingRule(FailureRule):
    """
    Alternating Scheduled / FailedScheduling events
    within a short window.

    Indicates cluster instability or resource contention.
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
                    code="RESOURCE_CONTENTION",
                    message="Cluster resource availability fluctuated",
                    role="cluster_intermediate",
                ),
                Cause(
                    code="POD_PENDING_UNSTABLE",
                    message="Pod scheduling state is unstable due to cluster conditions",
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
