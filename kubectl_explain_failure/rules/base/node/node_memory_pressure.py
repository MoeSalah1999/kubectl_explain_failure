from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeMemoryPressureRule(FailureRule):
    name = "NodeMemoryPressure"
    category = "Node"
    priority = 22  # Same tier as DiskPressure-level node signals

    requires = {
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not node_objs:
            return False

        return any(
            any(
                cond.get("type") == "MemoryPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
            for node in node_objs.values()
        )

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        pressured_nodes = [
            name
            for name, node in node_objs.items()
            if any(
                cond.get("type") == "MemoryPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_MEMORY_PRESSURE",
                    message=f"Node(s) under MemoryPressure: {', '.join(pressured_nodes)}",
                    blocking=True,
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod affected by Node MemoryPressure condition",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Node condition MemoryPressure=True detected",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": ["Node condition MemoryPressure=True"]
                    for name in pressured_nodes
                },
                f"pod:{pod_name}": ["Pod scheduled on node reporting MemoryPressure"],
            },
            "likely_causes": [
                "Node memory exhaustion",
                "High container memory consumption",
                "System daemons consuming node memory",
                "Memory leak in co-located workload",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {pressured_nodes[0]}"
                    if pressured_nodes
                    else "kubectl describe node <node>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check node memory usage (free -m)",
                "Inspect container memory limits and requests",
                "Consider scaling workload or draining node",
            ],
        }
