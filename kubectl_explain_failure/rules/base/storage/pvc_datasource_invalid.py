from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCDataSourceInvalidRule(FailureRule):
    """
    Detects PersistentVolumeClaims whose dataSource / dataSourceRef
    references an invalid, unsupported, missing, or unusable source.

    Real-world behavior:
    - PVC cloning requires a valid source PVC in the same namespace.
    - VolumeSnapshot restores require a valid VolumeSnapshot.
    - The referenced object may not exist.
    - The referenced API group/kind may be unsupported.
    - Controllers commonly emit:
        * data source not found
        * unsupported data source
        * invalid dataSource
        * VolumeSnapshot does not exist
        * source PVC not found
        * cloning source PVC not found
    - Provisioning remains blocked until the data source becomes valid.

    Exclusions:
    - StorageClass provisioning failures.
    - CSI driver provisioning failures after source validation succeeds.
    - Snapshot controller failures unrelated to source existence.
    - Generic Pending PVCs with no datasource configured.
    """

    name = "PVCDataSourceInvalid"
    category = "Storage"
    severity = "High"
    priority = 94
    deterministic = True

    requires = {
        "objects": ["pvc"],
        "optional_objects": [
            "volumesnapshot",
            "persistentvolumeclaim",
            "pvc",
        ],
    }

    blocks = [
        "PVCProvisioningFailed",
        "VolumeSnapshotClassMissing",
        "VolumeSnapshotContentMissing",
    ]

    INVALID_MARKERS = (
        "invalid datasource",
        "invalid data source",
        "unsupported datasource",
        "unsupported data source",
        "datasource not found",
        "data source not found",
        "failed to find datasource",
        "failed to find data source",
        "cannot find datasource",
        "cannot find data source",
        "snapshot not found",
        "volumesnapshot not found",
        "source pvc not found",
        "clone source pvc not found",
        "failed to get snapshot",
        "failed to get pvc",
        "source does not exist",
        "referenced object not found",
    )

    SUPPORTED_KINDS = {
        ("", "PersistentVolumeClaim"),
        ("snapshot.storage.k8s.io", "VolumeSnapshot"),
    }

    def _all_pvcs(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("pvc", {}) or {}

    def _all_snapshots(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("volumesnapshot", {}) or {}

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "<unknown>")

    def _datasource(
        self,
        pvc: dict[str, Any],
    ) -> dict[str, Any] | None:
        spec = pvc.get("spec", {}) or {}

        source_ref = spec.get("dataSourceRef")
        if isinstance(source_ref, dict):
            return source_ref

        source = spec.get("dataSource")
        if isinstance(source, dict):
            return source

        return None

    def _event_indicates_invalid_source(
        self,
        events: list[dict[str, Any]],
        pvc_name: str,
    ) -> bool:
        pvc_name = pvc_name.lower()

        for event in events:
            msg = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()
            text = f"{reason} {msg}"

            if pvc_name and pvc_name not in text:
                continue

            if any(marker in text for marker in self.INVALID_MARKERS):
                return True

        return False

    def _find_failure(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], str] | None:
        pvcs = self._all_pvcs(context)
        snapshots = self._all_snapshots(context)

        for pvc in pvcs.values():
            if not isinstance(pvc, dict):
                continue

            source = self._datasource(pvc)
            if not source:
                continue

            pvc_ns = self._namespace(pvc)

            kind = str(source.get("kind") or "")
            api_group = str(source.get("apiGroup") or "")
            source_name = str(source.get("name") or "")

            # Unsupported kind/group
            if (api_group, kind) not in self.SUPPORTED_KINDS:
                return (
                    pvc,
                    (f"Unsupported PVC data source " f"{api_group or '<core>'}/{kind}"),
                )

            # PVC clone source validation
            if kind == "PersistentVolumeClaim":
                source_pvc = pvcs.get(source_name)

                if not source_pvc:
                    return (
                        pvc,
                        f"Source PVC '{source_name}' does not exist",
                    )

                source_ns = self._namespace(source_pvc)

                # Kubernetes clone restriction:
                # source PVC must be same namespace.
                if source_ns != pvc_ns:
                    return (
                        pvc,
                        (
                            f"Source PVC '{source_name}' exists in namespace "
                            f"'{source_ns}' but cloning requires the same namespace"
                        ),
                    )

            # VolumeSnapshot restore validation
            elif kind == "VolumeSnapshot":
                snapshot = snapshots.get(source_name)

                if not snapshot:
                    return (
                        pvc,
                        f"VolumeSnapshot '{source_name}' does not exist",
                    )

                snapshot_ns = self._namespace(snapshot)

                if snapshot_ns != pvc_ns:
                    return (
                        pvc,
                        (
                            f"VolumeSnapshot '{source_name}' exists in namespace "
                            f"'{snapshot_ns}' but PVC restore requires the same namespace"
                        ),
                    )

        # Event-driven fallback
        for pvc in pvcs.values():
            pvc_name = self._name(pvc)

            if self._event_indicates_invalid_source(
                events,
                pvc_name,
            ):
                return (
                    pvc,
                    "Provisioning events report an invalid PVC data source",
                )

        return None

    def matches(self, pod, events, context) -> bool:
        return self._find_failure(events, context) is not None

    def explain(self, pod, events, context):
        match = self._find_failure(events, context)

        if match is None:
            raise ValueError("PVCDataSourceInvalid explain() called without a match")

        pvc, failure_reason = match

        pvc_name = self._name(pvc)
        namespace = self._namespace(pvc)

        source = self._datasource(pvc) or {}

        source_kind = str(source.get("kind") or "<unknown>")
        source_name = str(source.get("name") or "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_USES_DATASOURCE",
                    message=(
                        "PersistentVolumeClaim requests population from a data source"
                    ),
                    role="configuration",
                ),
                Cause(
                    code="PVC_DATASOURCE_INVALID",
                    message=failure_reason,
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_PROVISIONING_BLOCKED",
                    message=(
                        "The provisioner cannot create the volume until the "
                        "data source is valid"
                    ),
                    role="storage_failure",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": failure_reason,
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (
                    f"PVC {namespace}/{pvc_name} references "
                    f"{source_kind} '{source_name}' as its data source"
                ),
                failure_reason,
                (
                    "PVC provisioning cannot proceed until the referenced "
                    "data source becomes valid"
                ),
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": [
                    failure_reason,
                ]
            },
            "likely_causes": [
                "The referenced source PVC was deleted",
                "The referenced VolumeSnapshot was deleted",
                "The dataSource kind or apiGroup is unsupported",
                "The source object exists in a different namespace",
                "The PVC was restored from an outdated manifest that references a non-existent source",
                "The CSI snapshot components required for VolumeSnapshot restores are not installed",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name} -n {namespace}",
                f"kubectl get pvc -n {namespace}",
                f"kubectl get volumesnapshot -n {namespace}",
                "Verify spec.dataSource and spec.dataSourceRef",
                "Verify the referenced object exists and is in the same namespace",
                "Check external-provisioner and snapshot-controller logs",
            ],
        }
