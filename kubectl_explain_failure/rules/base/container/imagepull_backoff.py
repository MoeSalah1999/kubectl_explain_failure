from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImagePullBackOffRule(FailureRule):
    """
    Image pull repeatedly failed, Kubernetes entered backoff state.
    → Repeated pull retries
    """

    name = "ImagePullBackOff"
    category = "Image"
    priority = 45

    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    deterministic = False
    blocks = []

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return timeline_has_pattern(
            timeline,
            [{"reason": "ImagePullBackOff"}],
        )

    def explain(self, pod, events, context):
        retries = sum(1 for e in events if e.get("reason") == "ImagePullBackOff")
        confidence = min(0.7 + retries * 0.05, 0.92)

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_RETRY",
                    message="Kubernetes retrying failed image pull",
                    blocking=True,
                    role="runtime_root",
                )
            ]
        )

        return {
            "root_cause": "Image pull repeatedly failing (ImagePullBackOff)",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": ["Repeated ImagePullBackOff events"],
            "likely_causes": [
                "Image does not exist",
                "Registry unreachable",
                "Authentication failure",
            ],
            "suggested_checks": [
                "Verify image name and tag",
                "Check registry connectivity",
                "Inspect imagePullSecrets",
            ],
        }
