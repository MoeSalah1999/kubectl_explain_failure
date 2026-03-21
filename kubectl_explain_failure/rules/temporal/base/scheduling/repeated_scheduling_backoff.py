from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class RepeatedSchedulingBackoffRule(FailureRule):
    """
    Detects Pods repeatedly failing scheduling due to backoff.
    Real-world scheduler behavior often retries scheduling multiple times
    within short intervals before marking the pod as Pending/Unschedulable.
    """

    name = "RepeatedSchedulingBackoff"
    category = "Scheduling"
    priority = 85
    deterministic = False  # depends on observed event timeline
    requires = {"context": ["timeline"]}

    # Minimum number of backoff events to trigger this rule
    threshold: int = 3
    # Observation window in minutes to consider repeated failures
    window_minutes: int = 10

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        # Look for FailedScheduling + BackOff in the recent window
        recent_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )

        count_backoff = sum(
            1 for e in recent_events if "backoff" in (e.get("message") or "").lower()
        )

        return count_backoff >= self.threshold

    def explain(self, pod: dict, events: list[dict], context: dict) -> dict:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return {
                "root_cause": "Unknown",
                "confidence": 0.0,
                "evidence": [],
                "likely_causes": [],
                "suggested_checks": [],
                "causal_chain": CausalChain(causes=[]),
                "blocking": False,
                "object_evidence": {},
            }

        recent_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )

        backoff_events = [
            e for e in recent_events if "backoff" in (e.get("message") or "").lower()
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="TIMELINE_OBSERVED",
                    message=f"{len(backoff_events)} FailedScheduling events observed in last {self.window_minutes} minutes",
                    role="temporal_context",
                ),
                Cause(
                    code="SCHEDULER_RETRY",
                    message="Kubernetes scheduler triggered retry/backoff logic for Pod placement",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="REPEATED_FAILED_SCHEDULING",
                    message="Pod repeatedly failed scheduling due to insufficient resources or scheduling constraints",
                    role="scheduling_root",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains in Pending state with BackOff events",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Repeated scheduling backoff",
            "confidence": min(1.0, len(backoff_events) / self.threshold),
            "evidence": [e.get("message") or "" for e in backoff_events],
            "likely_causes": [
                "Node resources insufficient",
                "Affinity/taints preventing scheduling",
                "Pod priority preemption issues",
            ],
            "suggested_checks": [
                "Check node capacity and resource requests",
                "Inspect pod scheduling constraints (taints, tolerations, affinity)",
                "Verify cluster autoscaler behavior if applicable",
            ],
            "causal_chain": chain,
            "blocking": False,
            "object_evidence": {},
        }
