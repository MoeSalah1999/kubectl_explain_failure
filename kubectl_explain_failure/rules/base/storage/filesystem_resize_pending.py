from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class FilesystemResizePendingRule(FailureRule):
    """
    Detects Pods blocked by a PersistentVolumeClaim waiting for filesystem resize.

    Signals:
    - PVC has condition FileSystemResizePending
    - Pod attempts to mount the volume
    - Mount operation fails or remains pending

    Interpretation:
    The PVC was resized successfully at the storage layer but the filesystem
    expansion must occur on the node when the volume is mounted. Until this
    operation completes, the Pod may remain blocked in Pending or
    ContainerCreating state.

    Scope:
    - PVC volume expansion lifecycle
    - Deterministic (PVC condition based)
    - Applies to Pods referencing resized PVCs

    Exclusions:
    - PVCs without resize operations
    - PVCs already resized successfully at filesystem level
    """

    name = "FilesystemResizePending"
    category = "PersistentVolumeClaim"
    priority = 48

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "FailedMount",
        "PVCMountFailed",
    ]

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})

        if not pvc_objs:
            return False

        pvc = next(iter(pvc_objs.values()))
        conditions = pvc.get("status", {}).get("conditions", [])

        resize_pending = any(
            c.get("type") == "FileSystemResizePending" and c.get("status") == "True"
            for c in conditions
        )

        if not resize_pending:
            return False

        timeline = context.get("timeline")

        # Confirm Pod attempted to mount volume
        if timeline and timeline_has_pattern(
            timeline,
            [{"reason": "FailedMount"}],
        ):
            return True

        # PVC state alone is sufficient signal
        return True

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})

        pvc_name = next(iter(pvc_objs), "<unknown>")
        pvc = pvc_objs.get(pvc_name, {})

        requested = pvc.get("spec", {}).get("resources", {}).get("requests", {}).get("storage")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_RESIZE_REQUESTED",
                    message=f"PVC '{pvc_name}' storage expansion requested",
                    role="volume_context",
                ),
                Cause(
                    code="FILESYSTEM_RESIZE_PENDING",
                    message="Filesystem resize must complete before volume can mount",
                    blocking=True,
                    role="volume_root",
                ),
                Cause(
                    code="VOLUME_MOUNT_BLOCKED",
                    message="Pod cannot mount the resized volume until filesystem expansion completes",
                    role="volume_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": "PersistentVolume filesystem resize pending",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} has FileSystemResizePending condition",
                "Filesystem expansion required before volume mount",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": [
                    "Condition FileSystemResizePending=True",
                    f"Requested storage expansion to {requested}",
                ]
            },
            "likely_causes": [
                "PVC resized but filesystem expansion not yet performed",
                "Node filesystem resize operation pending",
                "Storage driver requires remount for expansion",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                f"kubectl describe pod {pod_name}",
                "Verify filesystem resize support in storage driver",
            ],
            "blocking": True,
        }