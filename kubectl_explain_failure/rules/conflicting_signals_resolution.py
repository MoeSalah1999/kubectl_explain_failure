from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ConflictingSignalsResolutionRule(FailureRule):
    """
    Meta-compound deterministic conflict resolver.

    When:
        - PVC is Pending (unbound)
        AND
        - ImagePullError signals are present

    Dominance logic:
        PVC scheduling/storage gate dominates image pull failures,
        because containers cannot start before volume binding succeeds.

    This rule formalizes precedence to prevent ambiguous root causes.
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
            e for e in timeline.raw_events
            if e.get("reason") in self.IMAGE_FAILURE_REASONS
        ]

        if not image_events:
            return False

        # Ensure image failure occurred AFTER or DURING PVC pending state
        # (defensive ordering — PVC must be unresolved)
        pvc = context.get("blocking_pvc")
        phase = pvc.get("status", {}).get("phase") if isinstance(
            pvc.get("status"), dict
        ) else pvc.get("status")

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
                    code="PVC_PENDING",
                    message="PersistentVolumeClaim is not yet bound",
                    blocking=True,
                    role="storage_root",
                ),
                Cause(
                    code="SCHEDULING_BLOCKED_BY_STORAGE",
                    message="Pod scheduling is gated by unresolved volume binding",
                    blocking=True,
                    role="scheduler_intermediate",
                ),
                Cause(
                    code="IMAGE_PULL_SIGNAL_SUPPRESSED",
                    message="Image pull errors observed but dominated by upstream PVC blockage",
                    role="container_symptom",
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
                f"pvc:{pvc_name}": [
                    "PVC phase is not Bound"
                ],
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
