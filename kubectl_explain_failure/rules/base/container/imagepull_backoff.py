from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImagePullBackOffRule(FailureRule):
    """
    Image pull repeatedly failed, Kubernetes entered backoff state.
    Indicates runtime-level image retrieval failure.
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

        # Ensure timeline shows ImagePullBackOff
        if not timeline_has_pattern(
            timeline,
            [{"reason": "ImagePullBackOff"}],
        ):
            return False

        # Ensure at least one container is actually waiting with ImagePullBackOff
        for cs in pod.get("status", {}).get("containerStatuses", []):
            waiting = cs.get("state", {}).get("waiting")
            if waiting and waiting.get("reason") == "ImagePullBackOff":
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        # Count retry events
        retries = sum(1 for e in events if e.get("reason") == "ImagePullBackOff")

        # Confidence scales with retries but capped
        confidence = min(0.75 + retries * 0.04, 0.92)

        failing_containers = [
            cs.get("name")
            for cs in pod.get("status", {}).get("containerStatuses", [])
            if cs.get("state", {}).get("waiting", {}).get("reason") == "ImagePullBackOff"
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_RETRY",
                    message=(
                        f"Container(s) failing image pull with backoff: "
                        f"{', '.join(failing_containers)}"
                    ),
                    blocking=True,
                    role="root",
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Image pull repeatedly failing (ImagePullBackOff)",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Repeated ImagePullBackOff events",
                "Container.state.waiting.reason == ImagePullBackOff",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"ImagePullBackOff detected in container(s): {', '.join(failing_containers)}"
                ]
            },
            "likely_causes": [
                "Image does not exist",
                "Registry unreachable",
                "Authentication failure",
                "Invalid image tag",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl logs {pod_name} -n {namespace}",
                "Verify image name and tag",
                "Check registry connectivity",
                "Inspect imagePullSecrets",
            ],
        }