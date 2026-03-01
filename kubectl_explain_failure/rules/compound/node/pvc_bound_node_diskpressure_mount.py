from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCBoundNodeDiskPressureMountRule(FailureRule):
    """
    Detects Pods whose volumes fail to mount despite PVCs being Bound,
    because the hosting Node is under DiskPressure.

    Signals:
    - All referenced PVCs have status.phase=Bound
    - Node.status.conditions includes DiskPressure=True
    - FailedMount events observed in timeline

    Interpretation:
    Although PersistentVolumeClaims are successfully bound,
    the hosting Node is experiencing DiskPressure. As a result,
    the kubelet cannot complete volume mount operations,
    causing mount failures independent of PVC provisioning state.

    Scope:
    - Infrastructure + volume layer (Node health + mount lifecycle)
    - Deterministic (object-state + event correlation based)
    - Acts as a compound check to suppress generic FailedMount
    or NodeDiskPressure rules when disk pressure is the
    upstream cause of mount failure

    Exclusions:
    - Does not include unbound PVC provisioning failures
    - Does not include CSI driver misconfiguration unrelated to disk pressure
    - Does not include scheduling failures unrelated to volume mount
    """
    name = "PVCBoundNodeDiskPressureMount"
    category = "Compound"
    priority = 62

    # This compound rule supersedes simpler mount or node signals
    blocks = ["FailedMount", "NodeDiskPressure"]

    requires = {
        "objects": ["pvc", "node"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})
        node_objs = objects.get("node", {})
        timeline = context.get("timeline")

        if not pvc_objs or not node_objs or not timeline:
            return False

        # All PVCs must be Bound
        all_bound = all(
            pvc.get("status", {}).get("phase") == "Bound" for pvc in pvc_objs.values()
        )
        if not all_bound:
            return False

        # Node has DiskPressure=True
        disk_pressure = any(
            any(
                cond.get("type") == "DiskPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
            for node in node_objs.values()
        )
        if not disk_pressure:
            return False

        # --- Use timeline.events_within_window if possible ---
        mount_failed = False
        if hasattr(timeline, "events_within_window"):
            recent_mount_failures = timeline.events_within_window(
                minutes=60,  # configurable lookback
                reason="FailedMount"
            )
            if recent_mount_failures:
                mount_failed = True

        # Fallback to pattern match if no timestamps
        if not mount_failed:
            mount_failed = timeline_has_pattern(timeline, r"FailedMount")

        return mount_failed

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        objects = context.get("objects", {})
        pvc_names = list(objects.get("pvc", {}).keys())
        node_names = list(objects.get("node", {}).keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_CONFIRMED",
                    message=f"PVCs bound successfully: {', '.join(pvc_names)}",
                    role="volume_context",
                ),
                Cause(
                    code="NODE_DISK_PRESSURE",
                    message=f"Node(s) under DiskPressure: {', '.join(node_names)}",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_MOUNT_OPERATION_FAILED",
                    message="Kubelet mount operation failed due to node disk pressure",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_VOLUME_MOUNT_FAILED",
                    message="Pod volume mount failed while PVCs were Bound",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PVC bound but mount failed due to Node DiskPressure",
            "confidence": 0.98,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "All PVCs are Bound",
                "Node condition DiskPressure=True detected",
                "FailedMount events observed in timeline",
            ],
            "object_evidence": {
                **{f"pvc:{name}": ["PVC status phase=Bound"] for name in pvc_names},
                **{
                    f"node:{name}": ["Node condition DiskPressure=True"]
                    for name in node_names
                },
                f"pod:{pod_name}": [
                    "Volume mount failures observed while node under DiskPressure"
                ],
            },
            "likely_causes": [
                "Node disk space exhaustion",
                "Image layer accumulation filling node storage",
                "Ephemeral storage pressure",
                "CSI mount retries failing due to disk constraints",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check node disk usage (df -h)",
                "Inspect kubelet logs for mount errors",
                "Free disk space or cordon/drain affected node",
            ],
        }
