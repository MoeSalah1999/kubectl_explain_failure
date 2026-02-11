from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCMountFailureRule(FailureRule):
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
        pvc_objs = context.get("objects", {}).get("pvc", {})

        if not pvc_objs:
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
        pvc_names = [p.get("metadata", {}).get("name", "<unknown>") for p in pvc_objs.values()]

        # Defensive: fallback if timeline missing
        timeline = context.get("timeline")
        timeline_events = getattr(timeline, "events", timeline) if timeline else events

        # Evidence
        mount_fail_count = sum(
            1 for e in timeline_events if e.get("reason") == "FailedMount"
            or "MountVolume" in e.get("message", "")
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND",
                    message=f"PVCs bound: {', '.join(pvc_names)}"
                ),
                Cause(
                    code="MOUNT_FAILED",
                    message=f"Volume mount failed ({mount_fail_count} events)",
                    blocking=True
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
                f"Bound PVCs: {', '.join(pvc_names)}"
            ],
            "object_evidence": {
                **{f"pvc:{name}": ["PVC bound but mount failed"] for name in pvc_names},
                f"pod:{pod_name}": ["Pod experienced volume mount failures"]
            },
            "likely_causes": [
                "Node not ready / volume attach failure",
                "Storage backend misconfiguration",
                "Insufficient permissions for volume mount"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check node and volume events",
                "Inspect PVC and storage class configuration",
                "Verify CSI driver logs and permissions"
            ]
        }
