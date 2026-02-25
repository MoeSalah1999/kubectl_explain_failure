import re
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImagePullRule(FailureRule):
    """
    Generic image pull failure without specific authentication signal.
    """

    name = "ImagePullError"
    category = "Image"
    priority = 30
    deterministic = True
    container_states = ["waiting"]
    requires = {
        "context": ["timeline"],
    }
    blocks = []

    def matches(self, pod, events, context):
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Direct structured check — no pattern engine needed
        return timeline.repeated("ErrImagePull", threshold=1)

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_REFERENCE_SPECIFIED",
                    message="Pod references a container image",
                    role="workload_context",
                ),
                Cause(
                    code="IMAGE_PULL_FAILURE",
                    message="Kubelet failed to pull container image from registry",
                    role="infrastructure_root",
                ),
                Cause(
                    code="CONTAINER_WAITING_IMAGE_PULL",
                    message="Container remains in waiting state due to image pull failure",
                    blocking=True,
                    role="runtime_symptom",
                ),
            ]
        )
        container_evidence = []
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            waiting = state.get("waiting")
            if waiting and waiting.get("reason") == "ErrImagePull":
                # Extract image name from message
                msg = waiting.get("message", "")
                match = re.search(r"image '([^']+)'", msg)
                image_name = match.group(1) if match else msg
                container_evidence.append(
                    f"Container '{cs['name']}' failed to pull image '{image_name}'"
                )

        evidence_list = []
        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else (events or [])

        for e in raw_events:
            reason = e.get("reason")
            msg = e.get("message", "")
            if reason:
                evidence_list.append(f"{reason} - {msg}")

        return {
            "root_cause": "Container image could not be pulled",
            "confidence": 0.85,
            "blocking": True,
            "causes": chain,
            "evidence": ["Event: ErrImagePull"],
            "object_evidence": {f"pod:{pod['metadata']['name']}": container_evidence},
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
        }
