from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeSnapshotRestoreFailedRule(FailureRule):
    """
    Detects failures when restoring a volume from a VolumeSnapshot via CSI.

    Real-world interpretation:
    This occurs when:
    - CSI driver fails to create a volume from snapshot
    - Snapshot is missing, corrupted, or incompatible
    - StorageClass / parameters mismatch
    - Underlying cloud provider restore API fails
    - VolumeSnapshotContent is not ready or invalid

    Signals:
    - Repeated ProvisioningFailed or FailedCreate events
    - Messages referencing snapshot restore
    - Occurring within a short time window (retry loop)
    - Sustained duration (not transient)
    - No successful provisioning event

    Scope:
    - CSI snapshot restore lifecycle (PVC provisioning from snapshot)
    - Storage control plane (external-provisioner)

    Exclusions:
    - Standard PVC provisioning failures (non-snapshot)
    - Volume mount / attach failures (handled elsewhere)
    """

    name = "VolumeSnapshotRestoreFailed"
    category = "Storage"
    priority = 82

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Repeated provisioning failures ---
        recent_failures = timeline.events_within_window(
            5,
            reason="ProvisioningFailed",
        ) + timeline.events_within_window(
            5,
            reason="FailedCreate",
        )

        if len(recent_failures) < 3:
            return False

        # --- 2. Snapshot restore signal in messages ---
        snapshot_related = 0
        for e in recent_failures:
            msg = (e.get("message") or "").lower()
            if "snapshot" in msg or "restore" in msg:
                snapshot_related += 1

        if snapshot_related < 2:
            return False

        # --- 3. Ensure this is volume-related failure ---
        if not timeline.has(kind="Volume", phase="Failure"):
            return False

        # --- 4. Sustained retry duration ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in ("ProvisioningFailed", "FailedCreate")
        )

        if duration < 60:
            return False

        # --- 5. No successful provisioning ---
        # External provisioner emits "ProvisioningSucceeded"
        if timeline.count(reason="ProvisioningSucceeded") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant failure message
        dominant_msg = None
        if timeline:
            msgs: list[str] = [
                (e.get("message") or "")
                for e in (
                    timeline.events_within_window(5, reason="ProvisioningFailed")
                    + timeline.events_within_window(5, reason="FailedCreate")
                )
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SNAPSHOT_RESTORE_FAILED",
                    message="CSI failed to restore volume from snapshot",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_PROVISIONER_RETRY",
                    message="CSI external-provisioner repeatedly retries snapshot restore",
                    role="control_loop",
                ),
                Cause(
                    code="VOLUME_CREATION_BLOCKED",
                    message="Volume cannot be created from snapshot",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_WAITING_FOR_VOLUME",
                    message="Pod cannot start because restored volume is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Volume restoration from snapshot is failing, preventing PVC provisioning",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Repeated provisioning failures related to snapshot restore",
                "Snapshot-related errors detected in events",
                "Sustained provisioning retry duration (>60s)",
                "No successful volume provisioning observed",
                *(
                    ["Dominant provisioning error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "VolumeSnapshot or VolumeSnapshotContent not ready or missing",
                "CSI driver does not support snapshot restore for this StorageClass",
                "Snapshot corrupted or incompatible with target volume parameters",
                "Cloud provider restore API failure or quota issue",
                "Mismatch between snapshot and requested volume size or type",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe pvc",
                "kubectl get volumesnapshots",
                "kubectl describe volumesnapshot <snapshot-name>",
                "kubectl get volumesnapshotcontents",
                "Check CSI driver logs (external-provisioner)",
                "Verify StorageClass supports snapshot restore",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked waiting for volume restoration from snapshot"
                ]
            },
        }
