from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RWXBackendMountUnavailableRule(FailureRule):
    """
    Detects ReadWriteMany volumes whose backing shared filesystem
    infrastructure is unavailable.

    Real-world examples:

    - NFS server down
    - NFS export unavailable
    - CephFS MDS unavailable
    - EFS mount target unreachable
    - Azure Files backend unavailable
    - SMB/CIFS server unavailable
    - Longhorn Share Manager unavailable
    - Trident backend offline

    Characteristics:

    - PVC is already Bound
    - Scheduling succeeds
    - VolumeAttachment may succeed
    - kubelet repeatedly fails mount operation

    This rule intentionally targets runtime RWX backend failures
    rather than provisioning failures.
    """

    name = "RWXBackendMountUnavailable"
    category = "Storage"
    severity = "High"
    priority = 96
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "objects": ["pvc"],
        "optional_objects": [
            "pv",
            "storageclass",
        ],
    }

    blocks = [
        "FailedMount",
        "VolumeAttachmentFailed",
        "PVCProvisioningFailed",
    ]

    RWX_MODES = {
        "ReadWriteMany",
    }

    BACKEND_MARKERS = (
        # NFS
        "mount.nfs",
        "mount.nfs4",
        "nfs server",
        "stale file handle",
        "access denied by server",
        "rpc timeout",
        "rpc: timed out",
        "no route to host",
        # CephFS
        "cephfs",
        "mds",
        "ceph monitor",
        # EFS
        "amazon-efs-utils",
        "efs mount",
        "mount target",
        # Azure Files
        "azurefile",
        "azure file",
        # SMB
        "cifs",
        "smb",
        # Longhorn
        "share-manager",
        # Generic
        "connection refused",
        "connection timed out",
        "i/o timeout",
        "context deadline exceeded",
        "host is down",
        "network is unreachable",
    )

    MOUNT_FAILURE_REASONS = {
        "FailedMount",
        "FailedAttachVolume",
    }

    def _all_pvcs(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("pvc", {}) or {}

    def _all_pvs(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("pv", {}) or {}

    def _pod_pvcs(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pvc_objects = self._all_pvcs(context)

        result = []

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim")

            if not isinstance(claim, dict):
                continue

            claim_name = claim.get("claimName")

            if claim_name and claim_name in pvc_objects:
                result.append(pvc_objects[claim_name])

        return result

    def _is_rwx_pvc(
        self,
        pvc: dict[str, Any],
    ) -> bool:
        modes = set(pvc.get("spec", {}).get("accessModes", []) or [])

        return bool(modes & self.RWX_MODES)

    def _bound_pv(
        self,
        pvc: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        pvs = self._all_pvs(context)

        volume_name = pvc.get("spec", {}).get("volumeName")

        if volume_name:
            return pvs.get(volume_name)

        return None

    def _backend_mount_failure_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        reason = str(event.get("reason", "")).lower()
        message = str(event.get("message", "")).lower()

        if reason not in {r.lower() for r in self.MOUNT_FAILURE_REASONS}:
            return False

        return any(marker in message for marker in self.BACKEND_MARKERS)

    def _find_failure(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], str] | None:

        rwx_pvcs = [
            pvc for pvc in self._pod_pvcs(pod, context) if self._is_rwx_pvc(pvc)
        ]

        if not rwx_pvcs:
            return None

        for pvc in rwx_pvcs:

            phase = pvc.get("status", {}).get("phase")

            if phase != "Bound":
                continue

            pv = self._bound_pv(pvc, context)

            if pv is None:
                continue

            for event in events:

                if not self._backend_mount_failure_event(event):
                    continue

                return (
                    pvc,
                    pv,
                    str(event.get("message", "")),
                )

        return None

    def matches(self, pod, events, context) -> bool:
        return (
            self._find_failure(
                pod,
                events,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):

        match = self._find_failure(
            pod,
            events,
            context,
        )

        if match is None:
            raise ValueError(
                "RWXBackendMountUnavailable explain() called without match"
            )

        pvc, pv, event_message = match

        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        pv_name = pv.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RWX_VOLUME_BOUND",
                    message=("RWX volume provisioning completed successfully"),
                    role="runtime_context",
                ),
                Cause(
                    code="RWX_BACKEND_UNAVAILABLE",
                    message=("Shared filesystem backend is unavailable"),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_CANNOT_MOUNT_RWX_VOLUME",
                    message=("Node cannot mount the RWX filesystem"),
                    role="storage_failure",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "RWX storage backend is unavailable and the volume cannot be mounted"
            ),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} is already Bound",
                f"PersistentVolume {pv_name} exists",
                "Provisioning completed successfully",
                f"Mount failure observed: {event_message}",
                "Failure occurred during filesystem mount rather than provisioning",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": ["RWX PVC is Bound but mount operation fails"],
                f"pv:{pv_name}": [event_message],
            },
            "likely_causes": [
                "NFS server is down",
                "NFS export is unavailable",
                "CephFS MDS is unavailable",
                "Amazon EFS mount target is unreachable",
                "Azure Files backend is unavailable",
                "SMB/CIFS server is unreachable",
                "Longhorn Share Manager is unavailable",
                "Storage network connectivity failure exists between node and RWX backend",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                f"kubectl describe pv {pv_name}",
                "kubectl describe pod <pod>",
                "Inspect kubelet mount errors on the affected node",
                "Verify connectivity from node to RWX storage backend",
                "Check backend storage service health (NFS, CephFS, EFS, Azure Files, SMB, Longhorn, etc.)",
                "Verify export/share configuration and backend availability",
            ],
        }
