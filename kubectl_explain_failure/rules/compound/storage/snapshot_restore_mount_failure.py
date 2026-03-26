from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SnapshotRestoreThenMountFailureRule(FailureRule):
    """
    Detects a PVC restored from a VolumeSnapshot that bound successfully and
    later failed during attach or mount.
    """

    name = "SnapshotRestoreThenMountFailure"
    category = "Compound"
    priority = 91
    deterministic = True
    blocks = [
        "FailedMount",
        "PVCMountFailed",
        "VolumeAttachFailed",
    ]
    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
        "optional_objects": ["volumesnapshot", "pv"],
    }

    GENERIC_MOUNT_FAILURE_MARKERS = (
        "failed to mount volume",
        "mountvolume.setup failed",
        "mountvolume.setupat failed",
        "unable to attach or mount volumes",
        "failed to attach volume",
        "attachvolume.attach failed",
    )

    SPECIFIC_EXCLUSION_MARKERS = (
        "permission denied",
        "multi-attach",
        "already attached",
        "already exclusively attached",
        "device is busy",
        "device or resource busy",
        "volume mode",
        "raw block",
        "block device",
        "node affinity conflict",
        "volume node affinity conflict",
    )

    def _is_snapshot_backed_pvc(self, pvc: dict) -> bool:
        for key in ("dataSource", "dataSourceRef"):
            source = pvc.get("spec", {}).get(key) or {}
            if source.get("kind") == "VolumeSnapshot":
                return True
        return False

    def _referenced_snapshot_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            pvc = pvc_objects.get(claim_name)
            if claim_name and pvc and self._is_snapshot_backed_pvc(pvc):
                referenced[claim_name] = pvc

        return referenced

    def _generic_mount_failures(self, timeline) -> list[dict]:
        failures = []

        for event in timeline.raw_events:
            if event.get("reason") not in {"FailedMount", "FailedAttachVolume"}:
                continue

            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.SPECIFIC_EXCLUSION_MARKERS):
                continue
            if any(marker in message for marker in self.GENERIC_MOUNT_FAILURE_MARKERS):
                failures.append(event)

        return failures

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        snapshot_pvcs = self._referenced_snapshot_pvcs(pod, context)
        if not snapshot_pvcs:
            return False

        if any(
            pvc.get("status", {}).get("phase") != "Bound"
            for pvc in snapshot_pvcs.values()
        ):
            return False

        if not pod.get("spec", {}).get("nodeName") and not any(
            event.get("reason") == "Scheduled" for event in timeline.raw_events
        ):
            return False

        return bool(self._generic_mount_failures(timeline))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        pvc_names = sorted(self._referenced_snapshot_pvcs(pod, context))

        chain = CausalChain(
            causes=[
                Cause(
                    code="SNAPSHOT_RESTORE_SUCCESS",
                    message="PVC was restored successfully from a VolumeSnapshot",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Pod failed to attach or mount the restored volume",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because the restored volume cannot be used",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod cannot start because a snapshot-restored volume cannot be mounted"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC restored from snapshot but later attach or mount failed"
            ]

        return {
            "root_cause": "Pod cannot start because a snapshot-restored volume cannot be mounted",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "Referenced PVC is bound and sourced from a VolumeSnapshot",
                "Pod later reports attach or mount failures for that restored volume",
                "Specific mount causes like permission-denied or multi-attach are excluded",
            ],
            "likely_causes": [
                "Node-specific storage access problem after restore completed",
                "CSI attacher or kubelet cannot finish the post-restore mount sequence",
                "Restored volume exists but is not becoming usable on the target node",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "kubectl get volumesnapshot -o yaml",
                "Check CSI node and controller logs",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
