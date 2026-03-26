from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeDeviceConflictRule(FailureRule):
    """
    Detects explicit volume device conflicts where Kubernetes or the CSI driver
    reports that the volume cannot be attached or mounted because it is already
    in use or its device semantics do not match.
    """

    name = "VolumeDeviceConflict"
    category = "Storage"
    priority = 88
    deterministic = True

    blocks = [
        "VolumeAttachFailed",
        "FailedMount",
        "PVCMountFailed",
        "RepeatedMountRetry",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    CONFLICT_MARKERS = (
        "multi-attach error",
        "already attached",
        "already exclusively attached",
        "exclusively attached",
        "is already in use",
        "device is busy",
        "device or resource busy",
        "mount point busy",
        "target is busy",
        "volume mode",
        "raw block",
        "block device",
        "filesystem mode",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _matching_events(self, timeline) -> list[dict]:
        matches = []

        for event in timeline.raw_events:
            if event.get("reason") not in {"FailedAttachVolume", "FailedMount"}:
                continue

            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.CONFLICT_MARKERS):
                matches.append(event)

        return matches

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return bool(self._matching_events(timeline))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [
                (event.get("message") or "")
                for event in matched_events
                for _ in range(self._occurrences(event))
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

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
                "FailedAttachVolume or FailedMount event contains explicit conflict semantics",
                "Conflict points to multi-attach, busy-device, or volumeMode mismatch behavior",
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
                "kubectl get volumeattachments",
                "Verify volumeMode consistency across Pods and PVCs",
                "Inspect CSI driver logs for attachment errors",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked due to volume device conflict during attach or mount"
                ]
            },
        }
