from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class StorageBackendQuotaExceededRule(FailureRule):
    """
    Detects failures caused by storage backend capacity exhaustion or quota
    enforcement.

    Real-world behavior
    -------------------
    This rule models situations where the storage backend is healthy but
    refuses operations because capacity, quota, or allocation limits have
    been reached.

    Common examples:

    - Ceph pool full
    - Ceph nearfull/full cluster state
    - EBS account volume quota exceeded
    - Azure managed disk quota exceeded
    - GCE PD quota exceeded
    - Longhorn storage exhausted
    - Portworx capacity exhausted
    - NetApp volume full
    - NFS export out of space
    - Thin-provisioned datastore exhausted
    - Storage backend allocation limits exceeded

    Typical symptoms:

    - PVC provisioning failures
    - Volume expansion failures
    - Snapshot creation failures
    - Clone creation failures
    - CSI driver returns quota/capacity errors
    - Backend refuses new allocations

    Exclusions:

    - CSI sidecar failures
    - Storage backend outages
    - VolumeAttachment failures
    - StorageClass misconfiguration
    - Node filesystem pressure
    """

    name = "StorageBackendQuotaExceeded"
    category = "Storage"
    severity = "High"
    priority = 66
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "persistentvolumeclaim",
            "persistentvolume",
            "storageclass",
        ],
    }

    blocks = [
        "PVCProvisioningFailed",
        "PVCExpansionFailed",
        "VolumeResizeFailed",
        "VolumeSnapshotFailed",
    ]

    WINDOW_MINUTES = 60

    #
    # Backend-specific quota/capacity exhaustion signals.
    #
    QUOTA_MARKERS = (
        # Generic
        "storage quota exceeded",
        "allocation limit exceeded",
        "volume limit exceeded",
        "disk quota exceeded",
        "managed disk quota exceeded",
        "ebs quota exceeded",
        "persistent disk quota exceeded",
        # Ceph
        "pool full",
        "ceph cluster full",
        "ceph osd full",
        "ceph health_err",
        "nearfull",
        "backfillfull",
        "recoveryfull",
        # Cloud providers
        "volume limit exceeded",
        "disk quota exceeded",
        "managed disk quota exceeded",
        "ebs quota exceeded",
        "persistent disk quota exceeded",
        # Longhorn / Portworx
        "volume is too large",
        "insufficient storage",
        "storage pool full",
        # Filesystems / NAS
        "no space left on device",
        "filesystem full",
        "out of disk space",
        # VMware / arrays
        "datastore full",
        "datastore capacity exceeded",
    )

    #
    # Backend identifiers required to avoid stealing matches from
    # generic provisioning failures.
    #
    BACKEND_IDENTIFIERS = (
        "ceph",
        "rbd",
        "rados",
        "longhorn",
        "portworx",
        "netapp",
        "ontap",
        "pure",
        "iscsi",
        "nfs",
        "efs",
        "fsx",
        "ebs",
        "azure",
        "managed disk",
        "persistent disk",
        "gce",
        "vsan",
        "datastore",
        "storage backend",
    )

    #
    # Evidence that points to CSI sidecar/controller failures instead.
    #
    SIDECAR_IDENTIFIERS = (
        "external-provisioner",
        "external-resizer",
        "external-snapshotter",
        "csi-provisioner",
        "csi-resizer",
        "csi-snapshotter",
    )

    SIDECAR_FAILURE_MARKERS = (
        "crashloopbackoff",
        "leader election lost",
        "panic",
        "failed to sync",
        "connection refused",
        "deadline exceeded",
        "context deadline exceeded",
    )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _event_text(self, event: dict[str, Any]) -> str:
        return (f"{self._reason(event)} " f"{self._message(event)}").lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _quota_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = self._event_text(event)

            if any(marker in text for marker in self.QUOTA_MARKERS):
                matches.append(event)

        return matches

    def _backend_specific(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        """
        Require explicit evidence that the quota/capacity
        condition originated from the storage backend.

        Generic provisioning errors are handled by
        PVCProvisioningFailed / VolumeResizeFailed /
        VolumeSnapshotFailed and should not match here.
        """

        for event in events:
            text = self._event_text(event)

            #
            # Explicit backend/vendor reference.
            #
            if any(backend in text for backend in self.BACKEND_IDENTIFIERS):
                return True

            #
            # Backend-specific capacity signatures.
            #
            if any(
                marker in text
                for marker in (
                    "ceph cluster full",
                    "ceph osd full",
                    "pool full",
                    "nearfull",
                    "backfillfull",
                    "recoveryfull",
                    "datastore full",
                    "storage pool full",
                    "managed disk quota exceeded",
                    "ebs quota exceeded",
                    "persistent disk quota exceeded",
                )
            ):
                return True

        return False

    def _sidecar_failure_present(
        self,
        timeline: Timeline,
    ) -> bool:
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = self._event_text(event)

            if any(ident in text for ident in self.SIDECAR_IDENTIFIERS) and any(
                marker in text for marker in self.SIDECAR_FAILURE_MARKERS
            ):
                return True

        return False

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        quota_events = self._quota_events(timeline)

        if not quota_events:
            return None

        #
        # Prevent collisions with CSI controller outage rules.
        #
        if self._sidecar_failure_present(timeline):
            return None

        #
        # Require backend-specific quota evidence.
        #
        if not self._backend_specific(quota_events):
            return None

        occurrences = sum(self._occurrences(e) for e in quota_events)

        #
        # StorageBackendQuotaExceeded should only fire
        # when repeated backend-capacity evidence exists.
        #
        backend_specific_events = [
            e for e in quota_events if self._backend_specific([e])
        ]

        if len(backend_specific_events) < 1:
            return None

        if occurrences < 3:
            return None

        latest = self._message(quota_events[-1])

        return {
            "quota_events": quota_events,
            "occurrences": occurrences,
            "latest": latest,
            "object_evidence": {"timeline:storage-quota": [latest]},
        }

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(
                timeline,
                Timeline,
            )
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
            raise ValueError("StorageBackendQuotaExceeded requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "StorageBackendQuotaExceeded explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="STORAGE_ALLOCATION_REQUESTED",
                    message=("The workload requires backend storage allocation"),
                    role="runtime_context",
                ),
                Cause(
                    code="STORAGE_BACKEND_QUOTA_EXCEEDED",
                    message=(
                        "The storage backend has exhausted available "
                        "quota or capacity"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="STORAGE_OPERATION_REJECTED",
                    message=(
                        "Provisioning, expansion, snapshot, or clone "
                        "operations cannot be completed"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Pod {namespace}/{pod_name} is affected by "
                f"storage backend capacity or quota exhaustion"
            ),
            (
                f"Observed {candidate['occurrences']} quota-related "
                f"failure occurrence(s) during the incident window"
            ),
            (f"Latest quota failure: {candidate['latest']}"),
        ]

        return {
            "rule": self.name,
            "root_cause": ("Storage backend quota or capacity has been exhausted"),
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "Ceph pool has reached full capacity",
                "Cloud-provider disk quota has been exceeded",
                "Longhorn or Portworx storage pools are exhausted",
                "Datastore free space has been depleted",
                "NFS or NAS export is out of capacity",
                "Backend allocation limits have been reached",
                "Storage expansion exceeded backend limits",
            ],
            "suggested_checks": [
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe pvc <pvc>",
                "kubectl logs <csi-controller-pod>",
                "Check storage backend capacity dashboards",
                "Verify backend quota and allocation limits",
                "Check Ceph health and pool utilization",
                "Check cloud-provider storage quotas",
                "Verify datastore free-space levels",
            ],
        }
