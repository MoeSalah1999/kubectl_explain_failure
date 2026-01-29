from rules.base_rule import FailureRule

class ImagePullBackOffRule(FailureRule):
    name = "ImagePullBackOff"
    category = "Image"
    severity = "High"
    priority = 20
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
