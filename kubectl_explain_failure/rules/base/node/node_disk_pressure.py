from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class NodeDiskPressureRule(FailureRule):
    """
    Detects node-level disk pressure impacting Pod scheduling or stability.

    Signals:
    - Node.status.conditions[type="DiskPressure"].status == "True"
    - (For Pending Pods) recent FailedScheduling events or scheduling failures

    Interpretation:
    A node reports DiskPressure=True, indicating insufficient available
    filesystem resources. Under disk pressure, the scheduler may be unable
    to place new Pods on the node, or existing Pods may be subject to
    eviction policies. This condition blocks normal workload placement
    and cluster stability.

    Scope:
    - Node infrastructure condition
    - Deterministic (node state & event-based)
    - Captures scheduler and workload impact caused by disk resource exhaustion

    Exclusions:
    - Does not diagnose specific filesystem paths or partitions
    - Does not inspect kubelet eviction thresholds
    - Does not model image garbage collection behavior
    - Does not detect memory or PID pressure
    """

    name = "NodeDiskPressure"
    category = "Node"
    priority = 20

    requires = {
        "objects": ["node"],
        "context": ["timeline"],  # optional but enables event correlation
    }

    supported_phases = {"Pending", "Running"}

    # Node health dominates scheduler errors
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        # --- Detect DiskPressure nodes ---
        disk_pressure_nodes = []
        for node in node_objs.values():
            for cond in node.get("status", {}).get("conditions", []):
                if (
                    cond.get("type") == "DiskPressure"
                    and cond.get("status") == "True"
                ):
                    disk_pressure_nodes.append(node)
                    break

        if not disk_pressure_nodes:
            return False

        pod_phase = pod.get("status", {}).get("phase")

        timeline = context.get("timeline")

        # --- If pod is Pending, require scheduling signal ---
        if pod_phase == "Pending" and timeline:
            recent_sched = timeline.events_within_window(
                10,
                reason="FailedScheduling",
            )

            if recent_sched:
                return True

            if timeline.has(kind="Scheduling", phase="Failure"):
                return True

            return False

        # --- For Running pods, DiskPressure alone is valid ---
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

        pod_phase = pod.get("status", {}).get("phase")
        timeline = context.get("timeline")

        scheduler_blocked = False
        if timeline:
            if timeline.events_within_window(10, reason="FailedScheduling"):
                scheduler_blocked = True
            elif timeline.has(kind="Scheduling", phase="Failure"):
                scheduler_blocked = True

        causes = [
            Cause(
                code="NODE_DISK_PRESSURE",
                message="Node reports DiskPressure=True",
                role="infrastructure_root",
                blocking=True,
            )
        ]

        if scheduler_blocked:
            causes.append(
                Cause(
                    code="SCHEDULER_BLOCKED",
                    message="Scheduler cannot place pod on node",
                    role="control_plane_effect",
                )
            )

        if pod_phase == "Pending":
            causes.append(
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending due to scheduling constraints",
                    role="workload_symptom",
                )
            )

        chain = CausalChain(causes=causes)

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