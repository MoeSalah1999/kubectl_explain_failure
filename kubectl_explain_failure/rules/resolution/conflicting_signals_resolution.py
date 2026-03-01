from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ConflictingSignalsResolutionRule(FailureRule):
    """
    Detects Pods that report image pull failures while an
    associated PersistentVolumeClaim remains Pending, and
    resolves the conflict by enforcing storage-layer precedence.

    Signals:
    - PersistentVolumeClaim.status.phase is Pending
    - Pod events include ErrImagePull or ImagePullBackOff
    - Pod phase is Pending

    Interpretation:
    Volume binding occurs before container image retrieval
    in the Pod startup lifecycle. If the PersistentVolumeClaim
    is not bound, the Pod cannot progress to container startup.
    Image pull errors observed during this state are treated
    as secondary or speculative signals. The storage-layer
    binding failure deterministically dominates and is
    considered the true root cause.

    Scope:
    - Volume layer precedence resolution
    - Deterministic (state + event correlation)
    - Acts as a meta-compound suppression rule to prevent
    ambiguous multi-root attribution

    Exclusions:
    - Does not include PVCs already in Bound phase
    - Does not include standalone image pull failures
    - Does not include mount failures after successful binding
    """

    name = "ConflictingSignalsResolution"
    category = "Compound"
    priority = 95  # Must outrank pvc_imagepull and individual image rules

    # Explicitly suppress component signals
    blocks = [
        "PVCImagePull",
        "ImagePullError",
        "ErrImagePull",
        "ImagePullBackOff",
        "PVCUnmounted",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    container_states = ["waiting"]

    IMAGE_FAILURE_REASONS = {
        "ErrImagePull",
        "ImagePullBackOff",
        "Failed",
        "BackOff",
    }

    def matches(self, pod, events, context) -> bool:
        """
        Match only if:
        - Canonical blocking PVC exists (from normalize_context)
        - Image pull failure exists in timeline
        """

        # Engine canonical PVC signal
        if not context.get("blocking_pvc"):
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect image-related failure events
        image_events = [
            e
            for e in timeline.raw_events
            if e.get("reason") in self.IMAGE_FAILURE_REASONS
        ]

        if not image_events:
            return False

        # Ensure image failure occurred AFTER or DURING PVC pending state
        # (defensive ordering — PVC must be unresolved)
        pvc = context.get("blocking_pvc")
        phase = (
            pvc.get("status", {}).get("phase")
            if isinstance(pvc.get("status"), dict)
            else pvc.get("status")
        )

        if phase == "Bound":
            return False  # No longer conflicting

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        pvc = context.get("blocking_pvc") or {}
        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        # Attempt container extraction
        container_name = "<unknown>"
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            if "waiting" in state:
                container_name = cs.get("name", "<unknown>")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_SIGNAL_CONTEXT",
                    message="Image pull errors observed but storage gate precedes runtime stage",
                    role="execution_context",
                ),
                Cause(
                    code="PVC_BINDING_BLOCKED",
                    message="PersistentVolumeClaim is not bound, preventing Pod startup",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STARTUP_GATED_BY_VOLUME",
                    message="Pod cannot progress past scheduling due to unresolved volume binding",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending due to volume binding failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PVC pending dominates image pull errors (deterministic precedence)",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Unbound PersistentVolumeClaim detected",
                "Image pull failure events observed",
                "Storage gate precedes container runtime stage",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod remains Pending due to unresolved PVC binding"
                ],
                f"pvc:{pvc_name}": ["PVC phase is not Bound"],
                f"container:{container_name}": [
                    "Image pull errors present but not root cause"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "Verify StorageClass and provisioner health",
                "Check volume binding mode and node affinity",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }
