
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCBoundNodeDiskPressureMountRule(FailureRule):
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
            pvc.get("status", {}).get("phase") == "Bound"
            for pvc in pvc_objs.values()
        )

        if not all_bound:
            return False

        # Node has DiskPressure=True
        disk_pressure = any(
            any(
                cond.get("type") == "DiskPressure"
                and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
            for node in node_objs.values()
        )

        if not disk_pressure:
            return False

        # FailedMount signal via timeline (engine-native)
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
                    code="PVC_BOUND",
                    message=f"PVCs bound successfully: {', '.join(pvc_names)}",
                ),
                Cause(
                    code="NODE_DISK_PRESSURE",
                    message=f"Node(s) under DiskPressure: {', '.join(node_names)}",
                ),
                Cause(
                    code="MOUNT_FAILED",
                    message="Volume mount failed due to node disk pressure",
                    blocking=True,
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
                **{
                    f"pvc:{name}": ["PVC status phase=Bound"]
                    for name in pvc_names
                },
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
                f"kubectl describe node {node_names[0]}" if node_names else "kubectl describe node <node>",
                f"kubectl describe pod {pod_name}",
                "Check node disk usage (df -h)",
                "Inspect kubelet logs for mount errors",
                "Free disk space or cordon/drain affected node",
            ],
        }
