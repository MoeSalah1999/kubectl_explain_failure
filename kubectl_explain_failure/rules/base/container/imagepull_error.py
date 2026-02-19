import re

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImagePullRule(FailureRule):
    """
    Generic image pull failure without specific authentication signal.
    """

    name = "ImagePullError"
    category = "Image"
    priority = 30

    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    deterministic = False
    blocks = []

    def matches(self, pod, events, context):
        timeline = context.get("timeline")
        if not timeline:
            return False

        return timeline_has_pattern(
            timeline,
            [{"reason": "ErrImagePull"}],
        )

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_FAILURE",
                    message="Container image could not be pulled",
                    blocking=True,
                    role="runtime_root",
                )
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
        for e in events:
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
