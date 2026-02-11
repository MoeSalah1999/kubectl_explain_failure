from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class RapidRestartEscalationRule(FailureRule):
    name = "RapidRestartEscalation"
    category = "Compound"
    priority = 52

    # This compound rule supersedes simpler crash signals
    blocks = ["CrashLoopBackOff", "RepeatedCrashLoop"]

    requires = {"context": ["timeline"]}

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Defensive: use timeline.events to iterate
        timeline_events = getattr(timeline, "events", timeline)

        # Detect repeated BackOff events
        repeated_backoff = timeline_has_pattern(timeline, r"BackOff")

        backoff_events = [e for e in timeline_events if e.get("reason") == "BackOff"]

        return repeated_backoff and len(backoff_events) >= 3

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RAPID_RESTARTS",
                    message="Repeated BackOff events detected",
                    blocking=True,
                ),
            ]
        )
        timeline_events = getattr(context.get("timeline", []), "events", context.get("timeline", []))
        return {
            "rule": self.name,
            "root_cause": "Rapid container restart escalation detected",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"{len([e for e in timeline_events if e.get('reason')=='BackOff'])} BackOff events observed",
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
                f"pod:{pod_name}": [
                    "Multiple BackOff events detected within timeline"
                ]
            },
        }
