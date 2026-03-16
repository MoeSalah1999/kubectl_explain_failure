from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class RootCauseAmbiguityRule(FailureRule):
    """
    Detects situations where multiple independent rules match with
    comparable confidence and no clear dominance.

    Signals:
    - Timeline contains multiple failure signals
    - Different subsystems emit errors (e.g. image pull + probe failure)
    - No single causal chain clearly dominates

    Interpretation:
    The Pod exhibits multiple competing failure signals. The engine
    cannot deterministically determine a single root cause.

    Scope:
    - Engine reasoning layer
    - Diagnostic transparency

    Exclusions:
    - Single rule matches
    - Compound rules already dominating
    """

    name = "RootCauseAmbiguity"
    category = "Resolution"
    priority = 5  # very low — only triggers if nothing dominates

    requires = {
        "context": ["timeline"],
    }

    deterministic = False

    blocks = []

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Require at least two failure signals in the timeline
        failure_signals = 0

        for reason in [
            "FailedMount",
            "FailedScheduling",
            "BackOff",
            "CrashLoopBackOff",
            "ImagePullBackOff",
        ]:
            if timeline_has_pattern(timeline, [{"reason": reason}]):
                failure_signals += 1

        return failure_signals >= 2

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        root_msg = (
            "Multiple competing failure signals detected; "
            "root cause cannot be uniquely determined"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="MULTIPLE_FAILURE_SIGNALS",
                    message="Pod timeline contains multiple independent failure events",
                    role="diagnostic_context",
                ),
                Cause(
                    code="ROOT_CAUSE_AMBIGUOUS",
                    message="Engine cannot determine a single dominant root cause",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="AMBIGUITY_REPORTED",
                    message="Root cause remains ambiguous due to competing signals",
                    role="diagnostic_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_msg,
            "confidence": 0.5,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} shows multiple failure signals",
                "Timeline contains competing failure events",
            ],
            "likely_causes": [
                "Multiple subsystems failing simultaneously",
                "Underlying infrastructure instability",
                "Application and platform issues occurring together",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect Pod events for competing failure reasons",
                "Investigate image, storage, and node conditions simultaneously",
            ],
            "blocking": False,
        }
