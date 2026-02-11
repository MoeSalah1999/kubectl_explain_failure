from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImagePullRule(FailureRule):
    name = "ImagePullError"
    priority = 13

    def matches(self, pod, events, context):
        return has_event(events, "ImagePullBackOff") or has_event(
            events, "ErrImagePull"
        )

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
    priority = 11

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


class ImagePullBackOffRule(FailureRule):
    name = "ImagePullBackOff"
    category = "Image"
    severity = "High"
    priority = 12
    phases = ["Pending"]

    def matches(self, pod, events, context):
        return any(e.get("reason") == "ImagePullBackOff" for e in events)

    def explain(self, pod, events, context):
        retries = sum(1 for e in events if e.get("reason") == "ImagePullBackOff")
        confidence = min(0.6 + retries * 0.05, 0.9)

        return {
            "root_cause": "Container image could not be pulled",
            "confidence": confidence,
            "evidence": ["Repeated ImagePullBackOff events"],
            "likely_causes": [
                "Image does not exist",
                "Registry authentication failure",
            ],
            "suggested_checks": [
                "Verify image name and tag",
                "Check imagePullSecrets",
            ],
        }
