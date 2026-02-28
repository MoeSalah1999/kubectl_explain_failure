from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class RapidRestartEscalationRule(FailureRule):
    """
    Detects Pods experiencing rapid restart escalation, where multiple
    BackOff events occur within a defined time window, indicating
    persistent container instability.

    Signals:
    - Multiple BackOff events observed within a bounded time window
    - Restart frequency exceeds configured threshold

    Interpretation:
    The container is repeatedly crashing or failing health checks in
    quick succession. The restart frequency indicates an unstable
    execution state that prevents the Pod from achieving a steady
    Running condition.

    Scope:
    - Timeline + container health layer
    - Deterministic (event-frequency based)
    - Acts as a compound escalation check for restart storms

    Exclusions:
    - Does not include isolated or transient restarts below threshold
    - Does not identify the underlying crash reason (handled by other rules)
    """
    name = "RapidRestartEscalation"
    category = "Compound"
    priority = 52

    # This compound rule supersedes simpler crash signals
    blocks = ["CrashLoopBackOff"]

    requires = {"context": ["timeline"]}

    # Configurable window and threshold
    BACKOFF_WINDOW_MINUTES = 30
    BACKOFF_THRESHOLD = 3

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Use events_within_window to find recent BackOff events
        recent_backoffs = timeline.events_within_window(
            self.BACKOFF_WINDOW_MINUTES, reason="BackOff"
        )

        return len(recent_backoffs) >= self.BACKOFF_THRESHOLD

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        timeline = context.get("timeline")
        recent_backoffs = (
            timeline.events_within_window(self.BACKOFF_WINDOW_MINUTES, reason="BackOff")
            if timeline
            else []
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="BACKOFF_EVENTS_WINDOW",
                    message=f"{len(recent_backoffs)} BackOff events detected within {self.BACKOFF_WINDOW_MINUTES} minute window",
                    role="container_health_context",
                ),
                Cause(
                    code="RAPID_RESTART_ESCALATION",
                    message="Container restart frequency exceeds stability threshold",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_UNSTABLE",
                    message="Pod unable to reach stable running state due to restart storm",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Rapid container restart escalation detected",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"{len(recent_backoffs)} BackOff events observed in the last {self.BACKOFF_WINDOW_MINUTES} minutes"
            ],
            "likely_causes": [
                "Application crash loop",
                "Container misconfiguration",
                "Resource limits exceeded",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect pod logs for crash reasons",
                "Check container resource requests/limits",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Multiple BackOff events detected within recent timeline"]
            },
        }