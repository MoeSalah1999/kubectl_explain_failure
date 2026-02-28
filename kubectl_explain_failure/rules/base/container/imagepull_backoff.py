from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImagePullBackOffRule(FailureRule):
    """
    Detects Pods entering ImagePullBackOff due to repeated container image pull failures.

    Signals:
    - Timeline contains repeated 'ImagePullBackOff' events
    - Container state.waiting.reason == "ImagePullBackOff"

    Interpretation:
    The container image could not be pulled (missing, invalid, or unreachable), 
    causing the Kubelet to apply exponential restart backoff. The Pod cannot start.

    Scope:
    - Container runtime / Kubelet phase
    - Deterministic (event & state-based)
    - Blocks downstream image-dependent runtime failures

    Exclusions:
    - Does not include CrashLoopBackOff due to application crash
    - Does not include OOMKilled or configuration errors
    """

    name = "ImagePullBackOff"
    category = "Image"
    priority = 45
    deterministic = True
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }
    blocks = []

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Require at least one ImagePullBackOff event
        if not timeline.repeated("ImagePullBackOff", threshold=1):
            return False

        # Confirm container state reflects the backoff
        for cs in pod.get("status", {}).get("containerStatuses", []):
            waiting = cs.get("state", {}).get("waiting")
            if waiting and waiting.get("reason") == "ImagePullBackOff":
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        # Count retry events
        timeline = context.get("timeline")
        retries = timeline.count(reason="ImagePullBackOff") if timeline else 0

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
                    code="IMAGE_PULL_FAILURE",
                    message=(
                        f"Container image pull failing for: "
                        f"{', '.join(failing_containers)}"
                    ),
                    role="image_root",
                ),
                Cause(
                    code="IMAGE_PULL_BACKOFF",
                    message="Kubelet entered exponential backoff due to repeated pull failures",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNABLE_TO_RUN",
                    message="Pod cannot reach Running state due to image pull failures",
                    role="workload_symptom",
                ),
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