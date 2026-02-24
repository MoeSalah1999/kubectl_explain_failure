from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase, has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class PendingUnschedulableRule(FailureRule):
    """
    Compound rule for Pods stuck Pending due to unschedulable conditions.
    Aggregates multiple low-level scheduling failure signals.
    """

    name = "PendingUnschedulable"
    category = "Compound" 
    priority = 15
    blocks = []
    requires = {"context": ["timeline"]}
    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        # Only match if no higher-priority rule already indicates root cause
        suppressed = context.get("suppressed_rules", [])
        for r in [ "PVCBoundNodeDiskPressureMount", "NodeDiskPressure"]:
            if r in suppressed:
                return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # Check recent FailedScheduling events
        recent_failed_scheduling = timeline.events_within_window(
            15, reason="FailedScheduling"
        )
        failed_scheduling = len(recent_failed_scheduling) > 0

        # Node conditions
        node_conditions = context.get("node_conditions", {})
        node_pressure = node_conditions.get("DiskPressure", False) or node_conditions.get("MemoryPressure", False)

        # Match compound unschedulable if no PVC is blocking
        blocking_pvc = context.get("blocking_pvc")
        if blocking_pvc is None and (failed_scheduling or node_pressure):
            return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        # Aggregate multiple causes
        causes_list = []

        if has_event(events, "FailedScheduling"):
            causes_list.append(
                Cause(
                    code="FAILED_SCHEDULING",
                    message="Scheduler failed to place pod",
                    blocking=True,
                )
            )

        node_conditions = context.get("node_conditions", {})
        if node_conditions.get("DiskPressure"):
            causes_list.append(
                Cause(
                    code="NODE_DISK_PRESSURE",
                    message="One or more nodes under DiskPressure",
                    blocking=True,
                )
            )

        if node_conditions.get("MemoryPressure"):
            causes_list.append(
                Cause(
                    code="NODE_MEMORY_PRESSURE",
                    message="One or more nodes under MemoryPressure",
                    blocking=True,
                )
            )

        chain = CausalChain(causes=causes_list)

        root_cause_message = "Pod Pending due to unschedulable conditions"
        for cause in causes_list:
            if cause.code == "FAILED_SCHEDULING":
                root_cause_message += f" ({cause.code})"
                break

        object_evidence = {f"pod:{pod_name}, phase:Pending": ["Unschedulable"]}
        if node_conditions.get("DiskPressure") or node_conditions.get("MemoryPressure"):
            node_signals = []
            if node_conditions.get("DiskPressure"):
                node_signals.append("DiskPressure=True")
            if node_conditions.get("MemoryPressure"):
                node_signals.append("MemoryPressure=True")

            object_evidence["node:all_nodes"] = node_signals

        return {
            "root_cause": root_cause_message,
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} remains Pending",
                "FailedScheduling or node pressure events observed",
            ],
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node taints",
                "Insufficient resources",
                "Disk or Memory pressure on nodes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "Check resource requests, taints, and node pressure",
            ],
            "blocking": True,
        }
