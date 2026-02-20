from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class NodeDiskPressureRule(FailureRule):
    """
    Node reports DiskPressure=True
    → Scheduler cannot place pods
    → Pod remains Pending or scheduling fails
    """

    name = "NodeDiskPressure"
    category = "Node"
    priority = 20

    requires = {
        "objects": ["node"],
        "context": ["timeline"],  # optional but enables event correlation
    }

    supported_phases = {"Pending", "Running"}

    deterministic = True

    # Node health dominates scheduler errors
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        # Check actual node condition
        disk_pressure_nodes = []
        for node in node_objs.values():
            conditions = node.get("status", {}).get("conditions", [])
            for cond in conditions:
                if (
                    cond.get("type") == "DiskPressure"
                    and cond.get("status") == "True"
                ):
                    disk_pressure_nodes.append(node)
                    break

        if not disk_pressure_nodes:
            return False

        # Optional: strengthen signal with scheduling event correlation
        timeline = context.get("timeline")
        if timeline and timeline_has_pattern(
            timeline,
            [{"reason": "FailedScheduling"}],
        ):
            return True

        # Even without explicit scheduler event, DiskPressure=True is sufficient
        return True

    def explain(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})

        # Identify affected node(s)
        affected_nodes = []
        for node in node_objs.values():
            conditions = node.get("status", {}).get("conditions", [])
            for cond in conditions:
                if (
                    cond.get("type") == "DiskPressure"
                    and cond.get("status") == "True"
                ):
                    affected_nodes.append(node)
                    break

        node_names = [
            n.get("metadata", {}).get("name", "unknown-node")
            for n in affected_nodes
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_DISK_PRESSURE",
                    message="Node reports DiskPressure=True",
                    blocking=True,
                    role="infrastructure_root",
                ),
                Cause(
                    code="SCHEDULER_BLOCKED",
                    message="Scheduler cannot place pod on node",
                    role="control_plane_effect",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains unscheduled or Pending",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {}
        for name in node_names:
            key = f"node:{name}"
            object_evidence[key] = [
                "Node condition DiskPressure=True"
            ]

        return {
            "root_cause": "Node disk pressure",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Node condition DiskPressure=True",
                "Scheduler unable to place pod",
            ],
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node filesystem is full",
                "Image garbage collection not reclaiming space",
                "Container logs consuming excessive disk",
                "Ephemeral storage exhaustion",
            ],
            "suggested_checks": [
                "kubectl describe node <node>",
                "Check node disk usage (df -h)",
                "Review kubelet eviction thresholds",
                "Inspect image and log cleanup policies",
            ],
        }