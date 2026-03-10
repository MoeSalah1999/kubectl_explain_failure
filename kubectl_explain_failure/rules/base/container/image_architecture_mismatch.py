from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event

class ImageArchitectureMismatchRule(FailureRule):
    """
    Detects container failures caused by image/node architecture mismatch.

    Signals:
    - Pod events where the image pull fails due to architecture incompatibility
    - Common in clusters with mixed ARM and AMD nodes

    Interpretation:
    - The container runtime cannot start the container because the image 
        architecture does not match the node's architecture.
    - Typically occurs when an image is built for a different CPU architecture than the node.

    Scope:
    - Container runtime / Kubelet phase
    - Phases: Pending
    - Deterministic (state-based)
    - Blocks downstream ImagePullBackOff failures

    Exclusions:
    - Does not cover generic ImagePullBackOff caused by network, auth, or missing image
    """

    name = "ImageArchitectureMismatch"
    category = "Container"
    priority = 60
    deterministic = True
    blocks = ["ImagePullBackOff"]
    requires = {}

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_event(timeline, kind="Image", phase="Failure", source="node")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_NODE_DIVERSITY",
                    message="Cluster has mixed ARM/AMD nodes",
                    role="configuration_context",
                ),
                Cause(
                    code="IMAGE_ARCH_MISMATCH",
                    message="Pod image architecture does not match node architecture",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_START_BLOCKED",
                    message="Pod cannot start due to image architecture mismatch",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod failed due to image/node architecture mismatch",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod: {pod_name}",
                "Node and image architecture mismatch detected in events",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Architecture mismatch encountered"]},
            "likely_causes": [
                "Cluster has mixed ARM/AMD nodes",
                "Image was built for incompatible architecture",
            ],
            "suggested_checks": [f"kubectl describe pod {pod_name}"],
        }