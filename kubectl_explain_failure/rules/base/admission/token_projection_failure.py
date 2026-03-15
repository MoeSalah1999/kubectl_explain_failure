from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class TokenProjectionFailureRule(FailureRule):
    """
    Detects failures of projected service account tokens.

    Signals:
    - Event reason == "TokenProjectionFailure"
    - Timeline contains token projection failure events

    Interpretation:
    The projected service account token could not be mounted or refreshed in the Pod.
    This prevents the Pod from authenticating to the Kubernetes API or other services
    that rely on projected credentials.

    Scope:
    - RBAC & identity layer
    - Deterministic (event-driven)
    - Applies to Pods with projected service account tokens

    Exclusions:
    - Does not include unrelated service account mount errors
    """

    name = "TokenProjectionFailure"
    category = "Admission"  # matches other RBAC/admission rules
    priority = 45
    requires = {
        "context": ["timeline"],
        "objects": [],
    }
    deterministic = True
    blocks = ["ServiceAccountMissing", "ServiceAccountRBAC"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_pattern(timeline, [{"reason": "TokenProjectionFailure"}])

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SA_TOKEN_PROJECTED",
                    message="Pod requires a projected service account token",
                    role="identity_context",
                ),
                Cause(
                    code="TOKEN_PROJECTION_FAILED",
                    message="Projected service account token could not be mounted",
                    blocking=True,
                    role="identity_root",
                ),
                Cause(
                    code="TOKEN_SYMPTOM",
                    message="Pod cannot authenticate with projected credentials",
                    role="identity_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Projected service account token failure",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} has projected service account token",
                "Event: TokenProjectionFailure",
            ],
            "object_evidence": {},
            "likely_causes": [
                "Projected token mount failed",
                "Kubernetes API authentication unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check projected service account token volume",
                "Check Pod spec for serviceAccountName",
            ],
            "blocking": True,
        }
