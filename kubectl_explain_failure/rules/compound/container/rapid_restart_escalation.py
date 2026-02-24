from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class RapidRestartEscalationRule(FailureRule):
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
                    code="RAPID_RESTARTS",
                    message="Repeated BackOff events detected within time window",
                    blocking=True,
                )
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