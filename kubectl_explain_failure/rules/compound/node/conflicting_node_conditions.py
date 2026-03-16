from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ConflictingNodeConditionsRule(FailureRule):
    """
    Detects Pods impacted by multiple simultaneous Node pressure conditions.

    Signals:
    - Node reports multiple pressure conditions:
        * MemoryPressure
        * DiskPressure
        * PIDPressure
    - Pod experiences eviction or scheduling instability
    - Timeline may contain eviction-related events

    Interpretation:
    The node is under multiple resource pressures simultaneously.
    This can trigger aggressive eviction decisions or unstable
    scheduling outcomes because the kubelet must free resources
    across multiple dimensions.

    Scope:
    - Node health conditions
    - Compound resource pressure scenario

    Exclusions:
    - Single pressure condition only
    - Pods not scheduled on a node
    """

    name = "ConflictingNodeConditions"
    category = "Compound"
    priority = 75

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "NodeMemoryPressure",
        "NodeDiskPressure",
        "NodePIDPressure",
        "EvictedRule",
    ]

    @staticmethod
    def _condition_true(value) -> bool:
        if value is True:
            return True
        if isinstance(value, dict):
            return str(value.get("status", "")).lower() == "true"
        return False

    def matches(self, pod, events, context) -> bool:
        node_conditions = context.get("node_conditions", {})
        if not node_conditions:
            return False

        pressures = [
            cond
            for cond in ["MemoryPressure", "DiskPressure", "PIDPressure"]
            if self._condition_true(node_conditions.get(cond))
        ]

        if len(pressures) < 2:
            return False

        timeline = context.get("timeline")

        # Optional timeline reinforcement
        if timeline and timeline_has_pattern(
            timeline,
            [{"reason": "Evicted"}],
        ):
            return True

        return True

    def explain(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})
        node_name = next(iter(node_objs), "<node>")

        node_conditions = context.get("node_conditions", {})

        active_pressures = [
            cond
            for cond in ["MemoryPressure", "DiskPressure", "PIDPressure"]
            if self._condition_true(node_conditions.get(cond))
        ]

        pressure_list = ", ".join(active_pressures)

        root_msg = (
            f"Node '{node_name}' is under multiple resource pressure conditions "
            f"({pressure_list}) causing unstable scheduling and eviction behavior"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PRESENT",
                    message=f"Pod scheduled on node '{node_name}'",
                    role="node_context",
                ),
                Cause(
                    code="MULTIPLE_NODE_PRESSURES",
                    message=f"Node reports simultaneous pressure conditions: {pressure_list}",
                    blocking=True,
                    role="infrastructure_root",
                ),
                Cause(
                    code="NODE_RESOURCE_CONTENTION",
                    message="Node resource contention leads to eviction or scheduling instability",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": root_msg,
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                f"Node conditions: {pressure_list}",
                "Multiple node pressure conditions detected",
            ],
            "object_evidence": {
                f"node:{node_name}": [f"Pressure conditions active: {pressure_list}"]
            },
            "likely_causes": [
                "Node resource exhaustion",
                "Disk and memory pressure occurring simultaneously",
                "Large number of Pods competing for node resources",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Check node resource usage (CPU, memory, disk)",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }
