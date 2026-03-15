from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class CRDConversionWebhookFailureRule(FailureRule):
    """
    Detects failures caused by CRD conversion webhooks.

    Signals:
    - Event message indicating conversion webhook failure
    - Timeline contains webhook conversion errors
    - Resource owned by a CustomResourceDefinition-backed controller

    Interpretation:
    Kubernetes attempted to convert a Custom Resource between API
    versions using the CRD conversion webhook, but the webhook
    failed or was unreachable. This prevents the controller from
    reconciling the resource.

    Scope:
    - Controller / API server CRD infrastructure
    - Deterministic (event-based)

    Exclusions:
    - Admission webhook denials
    - RBAC authorization failures
    """

    name = "CRDConversionWebhookFailure"
    category = "Controller"
    priority = 55

    deterministic = True

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect typical CRD conversion webhook errors
        return (
            timeline_has_pattern(timeline, r"conversion webhook")
            or timeline_has_pattern(timeline, r"failed calling webhook.*convert")
            or timeline_has_pattern(timeline, r"conversion webhook.*failed")
        )

    def explain(self, pod, events, context):
        owners = context.get("owners", [])

        owner_kind = owners[0].get("kind") if owners else "CustomResource"

        root_msg = "CRD conversion webhook failed during resource version conversion"

        chain = CausalChain(
            causes=[
                Cause(
                    code="CUSTOM_RESOURCE_OWNER_PRESENT",
                    message=f"Pod managed by {owner_kind} controller backed by a CustomResourceDefinition",
                    role="controller_context",
                ),
                Cause(
                    code="CRD_CONVERSION_WEBHOOK_FAILED",
                    message=root_msg,
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="CONTROLLER_RECONCILIATION_FAILED",
                    message="Controller cannot reconcile resource due to CRD conversion failure",
                    role="controller_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": root_msg,
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Event indicates CRD conversion webhook failure",
            ],
            "likely_causes": [
                "Conversion webhook service unavailable",
                "Webhook TLS certificate invalid or expired",
                "Webhook endpoint misconfigured",
                "CRD conversion strategy misconfigured",
            ],
            "suggested_checks": [
                "kubectl get crd -o yaml | grep conversion",
                "Check conversion webhook service endpoints",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }
