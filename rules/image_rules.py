from rules.base_rule import FailureRule
from explain_failure import get_pod_name, get_pod_phase, has_event

class ImagePullRule(FailureRule):
    name = "ImagePullError"
    priority = 50

    def matches(self, pod, events, context):
        return has_event(events, "ImagePullBackOff") or has_event(events, "ErrImagePull")

    def explain(self, pod, events, context):
        return {
            "root_cause": "Container image could not be pulled",
            "evidence": ["Event: ImagePullBackOff / ErrImagePull"],
            "likely_causes": [
                "Image name or tag does not exist",
                "Registry authentication failure",
                "Network connectivity issues",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "Check image name and tag",
                "Verify imagePullSecrets",
            ],
            "confidence": 0.95,
        }


class ImagePullSecretMissingRule(FailureRule):
    name = "ImagePullSecretMissing"
    priority = 40

    def matches(self, pod, events, context):
        return any("pull access denied" in e.get("message", "").lower() for e in events)

    def explain(self, pod, events, context):
        return {
            "root_cause": "Image pull secret missing or invalid",
            "evidence": ["Registry authentication error in event message"],
            "likely_causes": [
                "imagePullSecrets not defined",
                "Secret exists in wrong namespace",
            ],
            "suggested_checks": [
                "kubectl get secret",
                "kubectl describe pod <name>",
            ],
            "confidence": 0.96,
        }
