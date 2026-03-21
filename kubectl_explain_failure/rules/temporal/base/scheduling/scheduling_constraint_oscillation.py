from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SchedulingConstraintOscillationRule(FailureRule):
    """
    Detects oscillation in pod scheduling caused by alternating constraints:
    AffinityMatch → ResourceInsufficient → AffinityMatch → ResourceInsufficient.

    Real-world schedulers may retry scheduling a pod repeatedly if affinity
    constraints partially match but node resources are insufficient, resulting
    in a temporal oscillation of scheduling failures.
    """

    name = "SchedulingConstraintOscillation"
    category = "Scheduling"
    priority = 80
    deterministic = False
    requires = {"context": ["timeline"]}

    # Minimum number of oscillation cycles to trigger the rule
    threshold_cycles: int = 2
    window_minutes: int = 15  # Observation window

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        # Filter scheduling-related failures
        scheduling_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )
        reasons = [e.get("message", "").lower() for e in scheduling_events]

        # Look for repeated oscillation pattern
        oscillation_count = 0
        last_type = None
        for msg in reasons:
            if "affinity" in msg:
                if last_type == "resource":
                    oscillation_count += 1
                last_type = "affinity"
            elif "resources" in msg or "insufficient" in msg:
                if last_type == "affinity":
                    oscillation_count += 1
                last_type = "resource"
            else:
                last_type = None

        return oscillation_count >= self.threshold_cycles

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

        scheduling_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )
        backoff_events = [
            e
            for e in scheduling_events
            if "affinity" in (e.get("message") or "").lower()
            or "insufficient" in (e.get("message") or "").lower()
        ]

        causes = [
            Cause(
                code="AFFINITY_MATCH_FAILURE",
                message="Pod scheduling oscillated due to partial affinity matches",
                blocking=False,
                role="workload_context",
            ),
            Cause(
                code="RESOURCE_INSUFFICIENT",
                message="Node resources were insufficient for the pod, causing repeated failures",
                blocking=False,
                role="configuration_root",
            ),
            Cause(
                code="SCHEDULING_OSCILLATION",
                message=f"Observed {len(backoff_events)} scheduling failures with oscillating reasons",
                blocking=False,
                role="temporal_failure",
            ),
        ]

        chain = CausalChain(causes=causes)

        return {
            "root_cause": "Oscillating scheduling constraints",
            "confidence": min(1.0, len(backoff_events) / (self.threshold_cycles * 2)),
            "evidence": [e.get("message") or "" for e in backoff_events],
            "likely_causes": [
                "Partial node affinity constraints",
                "Node resource exhaustion",
                "Pod priority conflicts or preemption delays",
            ],
            "suggested_checks": [
                "Inspect pod affinity/anti-affinity rules",
                "Check node resource utilization",
                "Review cluster autoscaler or scheduling policies",
            ],
            "causal_chain": chain,
            "blocking": False,
            "object_evidence": {},
        }
