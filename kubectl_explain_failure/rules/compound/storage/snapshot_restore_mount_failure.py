from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SnapshotRestoreThenMountFailureRule(FailureRule):
    """
    Detects Pods failing because a PVC restore from a VolumeSnapshot
    succeeded but subsequent volume mount failed.

    Real-world interpretation:
    - PVC is created from a VolumeSnapshot
    - Snapshot restore succeeds but Pod cannot mount the volume
    - This represents a CSI driver/volume-level failure
    """

    name = "SnapshotRestoreThenMountFailure"
    category = "Compound"
    priority = 91
    deterministic = True
    blocks = [
        "PodMountFailure",
        "VolumeMountFailed",
        "PVCNotBound",
        "FailedMount",
    ]
    phases = ["Pending", "ContainerCreating"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc", "volumesnapshot", "pod"],
    }

    RESTORE_MARKERS = (
        "successfully restored snapshot",
        "restore completed",
    )

    MOUNT_FAILURE_MARKERS = (
        "failed to mount volume",
        "mountVolume.SetUp failed",
        "unable to attach or mount volumes",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Check if PVC references a VolumeSnapshot
        pvc_objects = context.get("objects", {}).get("pvc", {})
        snapshot_restored = False
        for pvc in pvc_objects.values():
            annotations = pvc.get("metadata", {}).get("annotations", {})
            if annotations.get("volume.kubernetes.io/selected-node") or annotations.get(
                "pv.kubernetes.io/bind-completed"
            ):
                snapshot_restored = True

        if not snapshot_restored:
            return False

        # Check timeline for mount failure signals after restore
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

        # Require at least one restore event followed by mount failure
        restore_events = [
            e
            for e in timeline.raw_events
            if any(
                marker in str(e.get("message", "")).lower()
                for marker in self.RESTORE_MARKERS
            )
        ]

        if not restore_events:
            return False

        # Ensure the restore precedes the mount failure
        restore_time = min(
            context["timeline"]._reference_time() for e in restore_events  # fallback
        )
        failure_time = max(
            context["timeline"]._reference_time() for e in mount_failures
        )

        if failure_time <= restore_time:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="SNAPSHOT_RESTORE_SUCCESS",
                    message="PVC was restored from VolumeSnapshot successfully",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Pod failed to mount the restored volume",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_DRIVER_FAILURE",
                    message="CSI driver or node-level issue prevents volume attachment/mount",
                    role="infrastructure_root",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because volume cannot be mounted",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": ["Pod cannot start because restored volume cannot mount"]
        }
        for pvc_name, _pvc in context.get("objects", {}).get("pvc", {}).items():
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC restored from snapshot but volume mount failed"
            ]

        return {
            "root_cause": "Pod cannot start because restored volume cannot be mounted",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "PVC restored from VolumeSnapshot successfully",
                "Pod container cannot mount the volume",
                "CSI driver logs indicate volume attach/mount failure",
            ],
            "likely_causes": [
                "CSI driver bug or crash",
                "Node does not have access to restored volume",
                "Volume topology or permissions prevent mount",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "kubectl get volumesnapshot -o yaml",
                "Check CSI driver logs on the node",
                "Inspect PV and node access permissions",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
