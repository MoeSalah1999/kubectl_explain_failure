from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCProvisionThenMountFailureRule(FailureRule):
    """
    Detects Pods where PVC provisioning succeeds but mounting fails.

    Real-world interpretation:
    - PVC is successfully bound to a PV
    - Pod fails at volume mount stage (AttachVolume/MountVolume errors)
    - Often caused by node affinity, multi-attach, or CSI driver errors
    """

    name = "PVCProvisionThenMountFailure"
    category = "Compound"
    priority = 90
    deterministic = True
    blocks = [
        "PodUnschedulable",
        "PVCNotBound",
        "VolumeBindingFailure",
        "FailedMount",
        "AttachVolumeFailed",
    ]
    phases = ["Pending", "ContainerCreating"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc", "pv", "storageclass", "node"],
    }

    PVC_BOUND_MARKERS = (
        "successfully bound",
        "provisioned",
    )

    MOUNT_FAILURE_MARKERS = (
        "failed to attach volume",
        "failed to mount volume",
        "multi-attach error",
        "node affinity conflict",
        "csi driver error",
        "volume not found",
    )

    def _referenced_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        objects = context.get("objects", {})
        pvc_objects = objects.get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]

        return referenced

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        referenced_pvcs = self._referenced_pvcs(pod, context)
        if not referenced_pvcs:
            return False

        # Must have at least one PVC bound
        bound_pvcs = [
            pvc
            for pvc in referenced_pvcs.values()
            if pvc.get("status", {}).get("phase") == "Bound"
        ]
        if not bound_pvcs:
            return False

        # Check for mount/attach failures in the timeline
        mount_failures = [
            e
            for e in timeline.raw_events
            if any(
                marker in str(e.get("message", "")).lower()
                for marker in self.MOUNT_FAILURE_MARKERS
            )
        ]
        if not mount_failures:
            return False

        # Optional: Require repeated mount failure signals
        if len(mount_failures) < 1:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        referenced_pvcs = self._referenced_pvcs(pod, context)
        pvc_names = sorted(referenced_pvcs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_SUCCESSFULLY",
                    message="PVC was successfully provisioned and bound to a PV",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Pod failed to mount the bound volume due to node/CSI constraints",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_CONTAINER_CREATING",
                    message="Pod remains Pending/ContainerCreating because volume mount never succeeds",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod cannot progress to running due to volume mount failures"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC is bound but Pod cannot mount volume"
            ]

        return {
            "root_cause": "Pod is stuck because PVC provision succeeded but volume mount failed",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Referenced PVCs are Bound",
                "Pod events indicate attach/mount failures",
                "Pod remains in Pending/ContainerCreating state",
            ],
            "likely_causes": [
                "Node does not satisfy PV affinity requirements",
                "Volume already attached to another node (multi-attach error)",
                "CSI driver reported mount failure or error",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "kubectl get pv -o wide",
                "Check node availability, volume attachments, and CSI driver logs",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
