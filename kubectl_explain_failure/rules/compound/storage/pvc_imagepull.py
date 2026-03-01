from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCThenImagePullFailRule(FailureRule):
    """
    Detects Pods that report ImagePullBackOff or ErrImagePull
    while an associated PersistentVolumeClaim is Pending,
    indicating that image retrieval failure is the primary
    blocker rather than volume availability.

    Signals:
    - PVC status.phase is Pending
    - Pod events include ImagePullBackOff or ErrImagePull

    Interpretation:
    Although the PersistentVolumeClaim is Pending, the Pod
    fails earlier during container image retrieval. Image
    pull failure prevents container startup before volume
    mounting occurs, making the image error the true
    blocking condition.

    Scope:
    - Execution layer (image retrieval phase)
    - Deterministic (object state + event based)
    - Acts as a compound suppression rule for PVC-related attribution

    Exclusions:
    - Does not include PVC-bound startup failures
    - Does not include scheduling failures
    - Does not include runtime crashes after successful image pull
    """
    name = "PVC Pending then ImagePullFail"
    category = "Compound"
    priority = 50
    blocks = ["ImagePullBackOff"]
    requires = {
        "objects": ["pvc"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        if not pvc:
            return False
        pvc_pending = pvc.get("status", {}).get("phase") == "Pending"
        return pvc_pending and any(
            has_event(events, r) for r in ["ImagePullBackOff", "ErrImagePull"]
        )

    def explain(self, pod, events, context):
        pvc = context["blocking_pvc"]
        pvc_name = pvc["metadata"]["name"]
        
        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING_CONTEXT",
                    message=f"PersistentVolumeClaim {pvc_name} is Pending",
                    role="volume_context",
                ),
                Cause(
                    code="IMAGE_PULL_FAILURE",
                    message="Container image could not be pulled (ImagePullBackOff or ErrImagePull)",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_STARTUP_BLOCKED",
                    message="Container startup blocked during image retrieval phase",
                    role="container_health_intermediate",
                ),
                Cause(
                    code="POD_NOT_READY",
                    message="Pod cannot become Ready due to image pull failure",
                    role="workload_symptom",
                ),
            ]
        )
        return {
            "root_cause": "Pod blocked by PVC Pending then failed to pull image",
            "confidence": 0.97,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} is Pending",
                "ImagePullBackOff or ErrImagePull observed",
            ],
            "object_evidence": {f"pvc:{pvc_name}": ["PVC not Bound"]},
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "Check image name and imagePullSecrets",
            ],
            "blocking": True,
        }
