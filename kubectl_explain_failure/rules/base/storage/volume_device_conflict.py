from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeDeviceConflictRule(FailureRule):
    """
    Detects volume device conflicts where a Pod cannot attach or mount
    a volume due to conflicting usage or incompatible device semantics.

    Real-world scenarios:
    - Volume already attached to another node (multi-attach violation)
    - Same volume used as both Block and Filesystem across Pods
    - Device path conflicts on node (e.g. /dev/xvdX already in use)
    - CSI driver rejects conflicting attachment mode

    Signals:
    - FailedAttachVolume or FailedMount events
    - Error messages indicating:
        - "already attached"
        - "multi-attach error"
        - "device is busy"
        - "volume mode conflict"
        - "block device vs filesystem mismatch"
    - Repeated failures within short window

    Scope:
    - Storage layer (volume attach/mount lifecycle)
    - Deterministic when conflict signals are explicit
    """

    name = "VolumeDeviceConflict"
    category = "Storage"
    priority = 88
    deterministic = True

    blocks = [
        "VolumeMountFailure",
        "VolumeAttachTimeout",
    ]

    phases = ["Pending", "ContainerCreating"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],  # ensures volume-backed workload context
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Look for relevant volume failure events ---
        recent_attach = timeline.events_within_window(5, reason="FailedAttachVolume")
        recent_mount = timeline.events_within_window(5, reason="FailedMount")

        failures = recent_attach + recent_mount

        if len(failures) < 2:
            return False  # avoid transient noise

        # --- 2. Detect conflict semantics in messages ---
        conflict_signals = 0

        for e in failures:
            msg = (e.get("message") or "").lower()

            if (
                "already attached" in msg
                or "multi-attach" in msg
                or "is already in use" in msg
                or "device is busy" in msg
                or "volume mode" in msg
                or "block device" in msg
                or "filesystem mode" in msg
                or "incompatible" in msg
            ):
                conflict_signals += 1

        if conflict_signals < 2:
            return False

        # --- 3. Ensure it's not progressing ---
        if timeline.count(reason="SuccessfulAttachVolume") > 0:
            return False

        if timeline.count(reason="Mounted") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        timeline = context.get("timeline")

        # Extract dominant error message
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(5)
                if e.get("reason") in ("FailedAttachVolume", "FailedMount")
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_DEVICE_CONFLICT",
                    message="Volume cannot be attached due to conflicting usage or device semantics",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="ATTACH_OR_MOUNT_FAILURE",
                    message="Kubelet or CSI driver fails to attach or mount the volume",
                    role="storage_intermediate",
                ),
                Cause(
                    code="POD_VOLUME_UNAVAILABLE",
                    message="Pod cannot access required volume and cannot start",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Volume device conflict prevents volume attachment or mount",
            "confidence": 0.97,
            "causes": chain,
            "evidence": [
                "Repeated FailedAttachVolume or FailedMount events",
                "Conflict-related error messages detected (multi-attach, device busy, or mode mismatch)",
                "No successful attach or mount observed",
                *(["Dominant error message: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "Volume already attached to another node (multi-attach violation)",
                "Same volume used with conflicting volumeMode (Block vs Filesystem)",
                "Device path already in use on node",
                "CSI driver enforcing exclusive access constraints",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe pvc",
                "kubectl describe pv",
                "Check VolumeAttachment objects (kubectl get volumeattachments)",
                "Verify volumeMode consistency across Pods and PVCs",
                "Inspect CSI driver logs for attachment errors",
                "Ensure volume is not mounted on another node",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked due to volume device conflict during attach/mount"
                ]
            },
        }
