from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class StorageBackendUnavailableRule(FailureRule):
    """
    Detects storage failures caused by the underlying storage backend being
    unavailable.

    Real-world behavior
    -------------------
    This rule models failures where Kubernetes and the CSI driver are healthy,
    but the actual storage system cannot service requests.

    Common examples:

    - Ceph cluster unavailable or degraded
    - EBS / Azure Disk / GCE PD API outage
    - NetApp controller outage
    - Pure Storage array unavailable
    - vSAN datastore unavailable
    - Longhorn control-plane outage
    - Portworx storage cluster outage
    - NFS server unavailable
    - iSCSI target unavailable
    - SAN fabric outage

    Typical symptoms:

    - PVC provisioning failures
    - AttachVolume failures
    - MountVolume failures
    - Snapshot failures
    - Resize failures
    - CSI driver healthy but returning backend errors

    This rule intentionally requires backend-specific evidence and should
    not trigger on generic CSI controller failures, sidecar failures,
    VolumeAttachment issues, or StorageClass misconfiguration.
    """

    name = "StorageBackendUnavailable"
    category = "Storage"
    severity = "High"
    priority = 92
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "persistentvolumeclaim",
            "persistentvolume",
            "storageclass",
            "pod",
        ],
    }

    blocks = [
        "PVCProvisioningFailed",
        "VolumeAttachmentStuck",
        "VolumeDetachStuck",
        "CSIExternalProvisionerUnavailable",
        "CSIExternalAttacherUnavailable",
        "CSIExternalResizerUnavailable",
        "CSIExternalSnapshotterUnavailable",
        "FailedMount",
    ]

    WINDOW_MINUTES = 60

    BACKEND_FAILURE_MARKERS = (
        #
        # Ceph
        #
        "ceph cluster is unavailable",
        "ceph health_err",
        "ceph health err",
        "rados timeout",
        "mon quorum lost",
        "failed to connect to ceph",
        #
        # RBD
        #
        "rbd image not accessible",
        #
        # Longhorn
        #
        "longhorn engine is not running",
        "volume is faulted",
        "replica scheduling failure",
        #
        # Portworx
        #
        "portworx cluster is down",
        "storage node unavailable",
        #
        # NFS
        #
        "nfs server not responding",
        "stale file handle",
        #
        # iSCSI
        #
        "iscsi login failed",
        "no active iscsi session",
        #
        # Storage arrays / SAN
        #
        "storage backend unavailable",
        "volume backend unavailable",
        "storage system unavailable",
        "backend unavailable",
        "backend is down",
        "array unavailable",
        "datastore unavailable",
        #
        # Explicit backend connectivity
        #
        "failed to connect to backend",
    )

    TRANSIENT_KEYWORDS = (
        "provisioning failed",
        "attachvolume.attach failed",
        "failedmount",
        "mountvolume.mountdevice failed",
    )

    CSI_SIDECAR_IDENTIFIERS = (
        "external-provisioner",
        "external-attacher",
        "external-resizer",
        "external-snapshotter",
        "csi-provisioner",
        "csi-attacher",
        "csi-resizer",
        "csi-snapshotter",
    )

    SIDECAR_FAILURE_MARKERS = (
        "crashloopbackoff",
        "leader election lost",
        "panic",
        "failed to sync",
        "failed to watch",
        "failed to list",
    )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _event_text(self, event: dict[str, Any]) -> str:
        return (f"{self._reason(event)} " f"{self._message(event)}").lower()

    def _backend_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = self._event_text(event)

            if any(marker in text for marker in self.BACKEND_FAILURE_MARKERS):
                failures.append(event)

        return failures

    def _has_backend_specific_evidence(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        backend_names = (
            "ceph",
            "rados",
            "rbd",
            "longhorn",
            "portworx",
            "netapp",
            "pure",
            "ontap",
            "iscsi",
            "nfs",
            "efs",
            "fsx",
            "ebs",
            "azure disk",
            "managed disk",
            "persistent disk",
            "gce pd",
            "vsan",
            "datastore",
            "storage backend",
            "volume backend",
            "storage system",
            "array",
        )

        for event in events:
            text = self._event_text(event)

            if any(backend in text for backend in backend_names):
                return True

        return False

    def _sidecar_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = self._event_text(event)

            if any(ident in text for ident in self.CSI_SIDECAR_IDENTIFIERS) and any(
                marker in text for marker in self.SIDECAR_FAILURE_MARKERS
            ):
                failures.append(event)

        return failures

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        backend_failures = self._backend_failure_events(timeline)

        if not backend_failures:
            return None

        #
        # Require backend-specific evidence.
        #
        if not self._has_backend_specific_evidence(backend_failures):
            return None

        #
        # Prevent collisions with CSI sidecar outage rules.
        #
        sidecar_failures = self._sidecar_failure_events(timeline)

        if sidecar_failures:
            return None

        #
        # Require repeated backend failures before matching.
        #
        occurrence_count = sum(self._occurrences(e) for e in backend_failures)

        if occurrence_count < 2:
            return None

        object_evidence: dict[str, list[str]] = {}

        latest_failure = self._message(backend_failures[-1])

        object_evidence["timeline:storage-backend"] = [latest_failure]

        return {
            "backend_failures": backend_failures,
            "object_evidence": object_evidence,
            "latest_failure": latest_failure,
            "occurrences": occurrence_count,
        }

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        if not isinstance(
            timeline,
            Timeline,
        ):
            raise ValueError("StorageBackendUnavailable requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("StorageBackendUnavailable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="STORAGE_OPERATION_REQUESTED",
                    message=(
                        "The workload requires storage operations "
                        "from the backend storage system"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="STORAGE_BACKEND_UNAVAILABLE",
                    message=(
                        "The underlying storage backend is "
                        "unavailable or unable to service requests"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_OPERATIONS_CANNOT_COMPLETE",
                    message=(
                        "Provisioning, attach, mount, resize, or "
                        "snapshot operations cannot complete"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (f"Pod {namespace}/{pod_name} is affected by " f"storage backend failures"),
            (
                f"Observed {candidate['occurrences']} backend "
                f"failure occurrence(s) during the incident window"
            ),
            (f"Latest backend failure: " f"{candidate['latest_failure']}"),
        ]

        return {
            "rule": self.name,
            "root_cause": ("Underlying storage backend is unavailable"),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "Ceph cluster outage or quorum loss",
                "Cloud block-storage service outage",
                "Storage array controller failure",
                "Longhorn or Portworx control-plane outage",
                "NFS server outage",
                "iSCSI target unavailable",
                "SAN fabric connectivity failure",
                "Storage backend network partition",
            ],
            "suggested_checks": [
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl logs <csi-controller-pod>",
                "Check storage backend health dashboards",
                "Verify backend API connectivity",
                "Verify storage cluster quorum and controller status",
                "Check CSI driver logs for backend connection failures",
                "Verify storage network connectivity",
            ],
        }
