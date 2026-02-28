from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImagePullSecretMissingCompoundRule(FailureRule):
    """
    Detects Pods that fail to start due to missing or invalid
    imagePullSecrets, causing ImagePullBackOff conditions.

    Signals:
    - FailedToRetrieveImagePullSecret events observed in pod timeline
    - ImagePullBackOff events observed following secret retrieval failure

    Interpretation:
    The Pod cannot authenticate to the container registry because
    the specified imagePullSecret is missing, invalid, or inaccessible.
    This prevents the container from being pulled, triggering
    ImagePullBackOff and blocking Pod startup.

    Scope:
    - Timeline + workload layer
    - Deterministic (event-based correlation)
    - Acts as a compound check for image authentication failures

    Exclusions:
    - Does not include network issues unrelated to image secrets
    - Does not include registry errors not caused by secrets
    """
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
                    code="IMAGE_PULL_SECRET_RETRIEVAL_FAILED",
                    message="Timeline shows FailedToRetrieveImagePullSecret events",
                    role="image_context",
                ),
                Cause(
                    code="IMAGE_PULL_SECRET_MISSING",
                    message="ImagePullSecret is missing, invalid, or inaccessible",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_BACKOFF",
                    message="Pod entered ImagePullBackOff due to authentication failure",
                    role="workload_symptom"
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
                f"pod:{pod_name}": ["Image pull secret retrieval failed"]
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get secret",
                "Verify imagePullSecrets configuration",
            ],
        }
