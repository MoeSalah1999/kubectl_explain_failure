from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImagePullSecretMissingRule(FailureRule):
    """
    Registry authentication failed due to missing or invalid imagePullSecret.
    → Image cannot be pulled
    → Container cannot start
    """

    name = "ImagePullSecretMissing"
    category = "Image"
    priority = 60

    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
        "objects": ["secret"],  # presence-based contract
    }

    deterministic = True
    blocks = ["ImagePullError"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not timeline_has_pattern(
            timeline,
            [{"reason": "ErrImagePull"}],
        ):
            return False

        for e in events:
            msg = e.get("message", "").lower()
            if "pull access denied" in msg or "unauthorized" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_SECRET_REFERENCE",
                    message="Pod references imagePullSecret",
                    role="workload_context",
                ),
                Cause(
                    code="IMAGE_PULL_SECRET_INVALID",
                    message="Registry authentication failed",
                    blocking=True,
                    role="config_root",
                ),
                Cause(
                    code="IMAGE_PULL_FAILURE",
                    message="Container image could not be pulled",
                    role="workload_symptom",
                ),
            ]
        )

        # Build object evidence for the secret(s) referenced by the pod
        secrets = pod.get("spec", {}).get("imagePullSecrets", [])
        object_evidence = {}
        for s in secrets:
            name = s.get("name")
            if name:
                key = f"secret:{name}"
                object_evidence[key] = [
                    "Secret referenced by pod exists but may be invalid"
                ]

        return {
            "root_cause": "Image pull secret missing or invalid",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Event: ErrImagePull",
                "Registry authentication error in event message",
            ],
            "object_evidence": object_evidence,
            "likely_causes": [
                "imagePullSecrets not defined",
                "Secret exists in wrong namespace",
                "Secret credentials invalid",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get secret",
                "Verify imagePullSecrets configuration",
            ],
        }
