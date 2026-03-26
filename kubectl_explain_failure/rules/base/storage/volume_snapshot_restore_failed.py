from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeSnapshotRestoreFailedRule(FailureRule):
    """
    Detects failures while provisioning a PVC from a VolumeSnapshot.

    Real-world behavior:
    - this should only apply to PVCs whose dataSource/dataSourceRef points to a
      VolumeSnapshot
    - generic provisioning failures without snapshot context should not match
    """

    name = "VolumeSnapshotRestoreFailed"
    category = "Storage"
    priority = 82
    deterministic = True

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
        "optional_objects": ["volumesnapshot"],
    }

    SNAPSHOT_MARKERS = (
        "snapshot",
        "restore",
        "volumesnapshot",
        "from snapshot",
        "snapshotcontent",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_snapshot_backed_pvc(self, pvc: dict) -> bool:
        for key in ("dataSource", "dataSourceRef"):
            source = pvc.get("spec", {}).get(key) or {}
            if source.get("kind") == "VolumeSnapshot":
                return True
        return False

    def _referenced_or_all_snapshot_pvcs(
        self, pod: dict, context: dict
    ) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            pvc = pvc_objects.get(claim_name)
            if claim_name and pvc and self._is_snapshot_backed_pvc(pvc):
                referenced[claim_name] = pvc

        if referenced:
            return referenced

        return {
            name: pvc
            for name, pvc in pvc_objects.items()
            if self._is_snapshot_backed_pvc(pvc)
        }

    def _matching_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            if event.get("reason") not in {"ProvisioningFailed", "FailedCreate"}:
                continue

            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.SNAPSHOT_MARKERS):
                matches.append(event)

        return matches

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        snapshot_pvcs = self._referenced_or_all_snapshot_pvcs(pod, context)
        if not snapshot_pvcs:
            return False

        if not any(
            pvc.get("status", {}).get("phase") != "Bound"
            for pvc in snapshot_pvcs.values()
        ):
            return False

        matched_events = self._matching_events(timeline)
        if not matched_events:
            return False

        if timeline.count(reason="ProvisioningSucceeded") > 0:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: e.get("reason") in {"ProvisioningFailed", "FailedCreate"}
        )

        if total_failures < 2 and duration < 60:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        pvc_names = sorted(self._referenced_or_all_snapshot_pvcs(pod, context)) or [
            "<unknown>"
        ]
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [
                (event.get("message") or "")
                for event in matched_events
                for _ in range(self._occurrences(event))
            ]
            dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SNAPSHOT_RESTORE_FAILED",
                    message="CSI failed to provision a volume from a snapshot source",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_PROVISIONER_RETRY",
                    message="CSI external-provisioner repeatedly retries the restore workflow",
                    role="control_loop",
                ),
                Cause(
                    code="POD_WAITING_FOR_VOLUME",
                    message="Pod cannot start because the restored volume is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Volume restoration from snapshot is failing, preventing PVC provisioning",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "PVC is requesting a volume from a VolumeSnapshot data source",
                "Provisioning failures explicitly mention snapshot or restore context",
                "No successful provisioning event was observed",
                *(
                    ["Dominant provisioning error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "VolumeSnapshot or VolumeSnapshotContent is not ready or is missing",
                "CSI driver does not support restoring this snapshot into the requested volume",
                "Snapshot metadata is incompatible with the target restore request",
                "Cloud or backend restore API rejected the request",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                *[f"kubectl describe pvc {pvc_name}" for pvc_name in pvc_names],
                "kubectl get volumesnapshots",
                "kubectl get volumesnapshotcontents",
                "Check CSI external-provisioner logs",
            ],
            "blocking": True,
            "object_evidence": {
                **{
                    f"pvc:{pvc_name}": [
                        "PVC is snapshot-backed and provisioning from snapshot failed"
                    ]
                    for pvc_name in pvc_names
                },
                f"pod:{pod_name}": [
                    "Pod is blocked waiting for a volume restored from snapshot"
                ],
            },
        }
