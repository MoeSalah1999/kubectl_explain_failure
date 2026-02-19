from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodePIDPressureRule(FailureRule):
    name = "NodePIDPressure"
    category = "Node"
    priority = 19  # Same tier as other node resource pressure signals

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
                cond.get("type") == "PIDPressure" and cond.get("status") == "True"
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
                cond.get("type") == "PIDPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PID_PRESSURE",
                    message=f"Node(s) under PIDPressure: {', '.join(pressured_nodes)}",
                    blocking=True,
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod affected by Node PIDPressure condition",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Node condition PIDPressure=True detected",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": ["Node condition PIDPressure=True"]
                    for name in pressured_nodes
                },
                f"pod:{pod_name}": ["Pod scheduled on node reporting PIDPressure"],
            },
            "likely_causes": [
                "Process ID exhaustion on node",
                "Excessive fork/exec activity",
                "Zombie processes not reaped",
                "Workload spawning uncontrolled child processes",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {pressured_nodes[0]}"
                    if pressured_nodes
                    else "kubectl describe node <node>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check process count on node (ps aux | wc -l)",
                "Inspect kubelet logs for PID pressure warnings",
                "Consider restarting offending workloads",
            ],
        }
