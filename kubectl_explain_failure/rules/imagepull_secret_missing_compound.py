from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


# ---------------------------------------------------------
# Compound: ImagePullBackOff caused by missing pull secret
# ---------------------------------------------------------

class ImagePullSecretMissingCompoundRule(FailureRule):
    name = "ImagePullSecretMissingCompound"
    category = "Compound"
    priority = 60

    # This supersedes simple image rules
    blocks = ["ImagePullError", "ImagePullSecretMissing"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        backoff = timeline_has_pattern(timeline, r"ImagePullBackOff")
        secret_error = timeline_has_pattern(
            timeline, r"FailedToRetrieveImagePullSecret"
        )

        return backoff and secret_error

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_SECRET_MISSING",
                    message="ImagePullSecret missing or invalid",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_BACKOFF",
                    message="ImagePullBackOff triggered due to authentication failure",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "ImagePullBackOff due to missing or invalid imagePullSecret",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "ImagePullBackOff events observed in timeline",
                "FailedToRetrieveImagePullSecret events observed in timeline",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Image pull secret retrieval failed"
                ]
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get secret",
                "Verify imagePullSecrets configuration",
            ],
        }