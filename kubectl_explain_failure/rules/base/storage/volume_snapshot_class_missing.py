from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeSnapshotClassMissingRule(FailureRule):
    """
    Detects VolumeSnapshot objects that cannot be processed because the
    referenced VolumeSnapshotClass does not exist.

    Real-world behavior:
    - A VolumeSnapshot may explicitly reference
      spec.volumeSnapshotClassName.
    - If that class has been deleted, renamed, never created, or is not
      installed on the cluster, snapshot creation remains blocked.
    - External snapshot-controller commonly emits events such as:
        * VolumeSnapshotClass not found
        * failed to get VolumeSnapshotClass
        * invalid VolumeSnapshotClass
    - VolumeSnapshot status is typically not Ready and no snapshot
      content can be provisioned.

    Exclusions:
    - Snapshot controller not installed.
    - CSI driver snapshot capability failures.
    - VolumeSnapshotContent binding failures.
    - Ready snapshots whose class exists.
    """

    name = "VolumeSnapshotClassMissing"
    category = "Storage"
    severity = "High"
    priority = 90
    deterministic = True

    requires = {
        "objects": ["volumesnapshot"],
        "optional_objects": [
            "volumesnapshotclass",
            "volumesnapshotcontent",
        ],
    }

    blocks = [
        "VolumeSnapshotProvisioningFailed",
        "VolumeSnapshotContentMissing",
    ]

    EVENT_MARKERS = (
        "volumesnapshotclass",
        "snapshot class",
    )

    NOT_FOUND_MARKERS = (
        "not found",
        "does not exist",
        "failed to get",
        "cannot find",
        "no such",
        "missing",
        "invalid volumesnapshotclass",
    )

    def _snapshot_objects(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("volumesnapshot", {}) or {}

    def _snapshotclass_objects(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("volumesnapshotclass", {}) or {}

    def _referenced_class(
        self,
        snapshot: dict[str, Any],
    ) -> str | None:
        spec = snapshot.get("spec", {}) or {}
        value = spec.get("volumeSnapshotClassName")
        return str(value) if value else None

    def _snapshot_ready(
        self,
        snapshot: dict[str, Any],
    ) -> bool:
        status = snapshot.get("status", {}) or {}

        if status.get("readyToUse") is True:
            return True

        for condition in status.get("conditions", []) or []:
            if condition.get("type") == "Ready" and condition.get("status") == "True":
                return True

        return False

    def _event_indicates_missing_class(
        self,
        events: list[dict[str, Any]],
        class_name: str,
    ) -> bool:
        class_name = class_name.lower()

        for event in events:
            msg = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()

            text = f"{reason} {msg}"

            if class_name not in text:
                continue

            if any(marker in text for marker in self.EVENT_MARKERS) and any(
                marker in text for marker in self.NOT_FOUND_MARKERS
            ):
                return True

        return False

    def _find_failure(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], str] | None:
        snapshots = self._snapshot_objects(context)
        snapshotclasses = self._snapshotclass_objects(context)

        for snapshot in snapshots.values():
            if not isinstance(snapshot, dict):
                continue

            class_name = self._referenced_class(snapshot)
            if not class_name:
                continue

            if class_name in snapshotclasses:
                continue

            if self._snapshot_ready(snapshot):
                continue

            return snapshot, class_name

        # Event-driven fallback
        for snapshot in snapshots.values():
            if not isinstance(snapshot, dict):
                continue

            class_name = self._referenced_class(snapshot)
            if not class_name:
                continue

            if self._event_indicates_missing_class(events, class_name):
                return snapshot, class_name

        return None

    def matches(self, pod, events, context) -> bool:
        return self._find_failure(events, context) is not None

    def explain(self, pod, events, context):
        match = self._find_failure(events, context)
        if match is None:
            raise ValueError(
                "VolumeSnapshotClassMissing explain() called without a match"
            )

        snapshot, class_name = match

        metadata = snapshot.get("metadata", {}) or {}
        snapshot_name = metadata.get("name", "<unknown>")
        namespace = metadata.get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUMESNAPSHOT_REFERENCES_CLASS",
                    message=("VolumeSnapshot references a VolumeSnapshotClass"),
                    role="configuration",
                ),
                Cause(
                    code="VOLUMESNAPSHOTCLASS_MISSING",
                    message=(
                        f"Referenced VolumeSnapshotClass '{class_name}' "
                        "does not exist"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SNAPSHOT_CANNOT_BE_CREATED",
                    message=("Snapshot controller cannot create or bind the snapshot"),
                    role="storage_failure",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                f"Referenced VolumeSnapshotClass '{class_name}' does not exist"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (
                    f"VolumeSnapshot {namespace}/{snapshot_name} references "
                    f"VolumeSnapshotClass '{class_name}'"
                ),
                (
                    f"VolumeSnapshotClass '{class_name}' is not present in "
                    "the cluster object graph"
                ),
                (
                    "The VolumeSnapshot is not Ready and cannot be processed "
                    "without a valid VolumeSnapshotClass"
                ),
            ],
            "object_evidence": {
                f"volumesnapshot:{snapshot_name}": [
                    f"References missing VolumeSnapshotClass '{class_name}'"
                ]
            },
            "likely_causes": [
                "The VolumeSnapshotClass was deleted after the snapshot was created",
                "The VolumeSnapshotClass name is misspelled",
                "Snapshot CRDs/controllers were installed without the expected class",
                "A cluster migration or restore omitted the VolumeSnapshotClass resource",
            ],
            "suggested_checks": [
                "kubectl get volumesnapshotclass",
                f"kubectl describe volumesnapshot {snapshot_name} -n {namespace}",
                (f"kubectl get volumesnapshotclass {class_name}"),
                "Verify the CSI snapshot driver created the expected VolumeSnapshotClass",
            ],
        }
