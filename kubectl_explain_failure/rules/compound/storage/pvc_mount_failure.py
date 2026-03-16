from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCMountFailureRule(FailureRule):
    """
    Detects Pods whose PersistentVolumeClaims are Bound but
    fail during the volume mount phase, preventing container
    startup.

    Signals:
    - All associated PVCs are in Bound phase
    - Pod events include FailedMount or MountVolume errors
    - No PV-level failure (Released/Failed) is present

    Interpretation:
    Although the PersistentVolumeClaim is successfully bound,
    the kubelet fails to mount the volume to the Pod. This
    indicates a volume-layer failure during the mount phase,
    blocking container initialization and preventing the Pod
    from progressing to Ready.

    Scope:
    - Volume layer (post-binding mount phase)
    - Deterministic (object state + event based)
    - Acts as a compound suppression rule for simple FailedMount signals

    Exclusions:
    - Does not include PVC Pending scenarios
    - Does not include PV Released or Failed root causes
    - Does not include container runtime crashes unrelated to volume mount
    """

    name = "PVCMountFailure"
    category = "Compound"
    priority = 54

    # This compound rule supersedes simpler FailedMount signals
    blocks = ["FailedMount"]

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],  # optional, allows timeline-based checks
    }

    def matches(self, pod, events, context) -> bool:
        pv_objs = context.get("objects", {}).get("pv", {})
        for pv in pv_objs.values():
            if pv.get("status", {}).get("phase") in ("Released", "Failed"):
                return False  # PV-level root cause takes precedence

        pvc_objs = context.get("objects", {}).get("pvc", {})

        if not pvc_objs:
            return False

        # Exclude filesystem resize pending PVCs (more specific root cause)
        for pvc in pvc_objs.values():
            conditions = pvc.get("status", {}).get("conditions", [])
            if any(
                c.get("type") == "FileSystemResizePending" and c.get("status") == "True"
                for c in conditions
            ):
                return False

        # All PVCs must be Bound
        all_bound = all(
            p.get("status", {}).get("phase") == "Bound" for p in pvc_objs.values()
        )

        # Detect FailedMount events via timeline if available
        timeline = context.get("timeline")
        failed_mount_timeline = False
        if timeline:
            failed_mount_timeline = timeline_has_pattern(timeline, r"MountVolume")

        # Also check events list as a fallback
        failed_mount_events = any(
            e.get("reason") == "FailedMount" or "MountVolume" in e.get("message", "")
            for e in events
        )

        return all_bound and (failed_mount_timeline or failed_mount_events)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        pvc_objs = context.get("objects", {}).get("pvc", {})
        pvc_names = [
            p.get("metadata", {}).get("name", "<unknown>") for p in pvc_objs.values()
        ]

        # Defensive: fallback if timeline missing
        timeline = context.get("timeline")
        timeline_events = getattr(timeline, "events", timeline) if timeline else events

        # Evidence
        mount_fail_count = sum(
            1
            for e in timeline_events
            if e.get("reason") == "FailedMount" or "MountVolume" in e.get("message", "")
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_CONTEXT",
                    message=f"PersistentVolumeClaim(s) successfully bound: {', '.join(pvc_names)}",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message=f"Volume mount failed ({mount_fail_count} events observed)",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_STARTUP_BLOCKED",
                    message="Container initialization blocked due to mount failure",
                    role="execution_intermediate",
                ),
                Cause(
                    code="POD_NOT_READY",
                    message="Pod cannot progress to Ready state due to mount failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PVC is bound but volume mount failed",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"{mount_fail_count} FailedMount or MountVolume events detected",
                f"Bound PVCs: {', '.join(pvc_names)}",
            ],
            "object_evidence": {
                **{f"pvc:{name}": ["PVC bound but mount failed"] for name in pvc_names},
                f"pod:{pod_name}": ["Pod experienced volume mount failures"],
            },
            "likely_causes": [
                "Node not ready / volume attach failure",
                "Storage backend misconfiguration",
                "Insufficient permissions for volume mount",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check node and volume events",
                "Inspect PVC and storage class configuration",
                "Verify CSI driver logs and permissions",
            ],
        }
