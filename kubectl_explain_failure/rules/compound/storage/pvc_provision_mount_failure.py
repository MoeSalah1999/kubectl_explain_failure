from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCProvisionThenMountFailureRule(FailureRule):
    """
    Detects Pods where PVC provisioning completed successfully and the Pod later
    failed during attach or mount.

    This rule intentionally stays generic and excludes more specific mount
    causes like permission denied, multi-attach conflicts, and node-affinity
    conflicts.
    """

    name = "PVCProvisionThenMountFailure"
    category = "Compound"
    priority = 90
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
        "optional_objects": ["pv", "storageclass", "node"],
    }

    GENERIC_MOUNT_FAILURE_MARKERS = (
        "unable to attach or mount volumes",
        "timed out waiting for the condition",
        "failed to attach volume",
        "failed to mount volume",
        "attachvolume.attach failed",
        "mountvolume.setup failed",
        "mountvolume.setupat failed",
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

    def _referenced_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]

        return referenced

    def _pvc_provisioning_succeeded(self, pvc: dict, context: dict) -> bool:
        if pvc.get("status", {}).get("phase") != "Bound":
            return False

        metadata = pvc.get("metadata", {})
        annotations = metadata.get("annotations", {}) or {}
        if annotations.get(
            "volume.kubernetes.io/storage-provisioner"
        ) or annotations.get("volume.beta.kubernetes.io/storage-provisioner"):
            return True

        volume_name = pvc.get("spec", {}).get("volumeName")
        pv_objects = context.get("objects", {}).get("pv", {})
        if volume_name:
            pv = pv_objects.get(volume_name, {})
            pv_annotations = pv.get("metadata", {}).get("annotations", {}) or {}
            if pv_annotations.get("pv.kubernetes.io/provisioned-by"):
                return True
            if volume_name.startswith("pvc-"):
                return True

        storageclass_name = pvc.get("spec", {}).get("storageClassName")
        storageclasses = context.get("objects", {}).get("storageclass", {})
        storageclass = storageclasses.get(storageclass_name, {})
        return bool(storageclass_name and storageclass.get("provisioner"))

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

        referenced_pvcs = self._referenced_pvcs(pod, context)
        if not referenced_pvcs:
            return False

        if any(
            pvc.get("status", {}).get("phase") != "Bound"
            for pvc in referenced_pvcs.values()
        ):
            return False

        if not pod.get("spec", {}).get("nodeName") and not any(
            event.get("reason") == "Scheduled" for event in timeline.raw_events
        ):
            return False

        provisioned_pvcs = [
            pvc
            for pvc in referenced_pvcs.values()
            if self._pvc_provisioning_succeeded(pvc, context)
        ]
        if not provisioned_pvcs:
            return False

        return bool(self._generic_mount_failures(timeline))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        referenced_pvcs = self._referenced_pvcs(pod, context)
        pvc_names = sorted(
            pvc_name
            for pvc_name, pvc in referenced_pvcs.items()
            if self._pvc_provisioning_succeeded(pvc, context)
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_SUCCESSFULLY",
                    message="PVC was successfully provisioned and bound to a PV",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Pod failed to mount the bound volume after provisioning completed",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_AFTER_PROVISIONING",
                    message="Pod remains Pending because post-provision attach or mount never succeeds",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod cannot progress to running after PVC provisioning completed"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC is bound and provisioned, but later attach or mount fails"
            ]

        return {
            "root_cause": "Pod is stuck because PVC provision succeeded but volume mount failed",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Referenced PVCs are Bound and show successful provisioning or binding evidence",
                "Pod events indicate a later attach or mount failure",
                "Specific mount causes like permission-denied or multi-attach are excluded",
            ],
            "likely_causes": [
                "CSI attacher or kubelet cannot complete the post-provision mount sequence",
                "Node-specific storage access issue after binding completed",
                "Backend volume was provisioned but never became usable on the target node",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "kubectl get pv -o wide",
                "Check node availability, volumeattachments, and CSI driver logs",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
