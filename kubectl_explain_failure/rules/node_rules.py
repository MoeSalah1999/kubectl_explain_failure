from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class EvictedRule(FailureRule):
    name = "Evicted"
    category = "Node"
    priority = 21  # Lower than compound rules like NodeNotReadyEvicted
    phases = ["Failed"]

    def matches(self, pod, events, context) -> bool:
        # Match Kubernetes eviction signal
        return has_event(events, "Evicted")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = pod.get("spec", {}).get("nodeName", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_EVICTED",
                    message="Pod was evicted from node",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod was evicted from node",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Event: Evicted",
                f"Pod {pod_name} entered Failed phase",
            ],
            "object_evidence": {f"pod:{pod_name}": [f"Evicted from node {node_name}"]},
            "likely_causes": [
                "Node memory pressure",
                "Node disk pressure",
                "Node resource exhaustion",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe node {node_name}",
                "Check node conditions (MemoryPressure, DiskPressure)",
            ],
            "blocking": True,
        }


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
                cond.get("type") == "MemoryPressure"
                and cond.get("status") == "True"
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
                cond.get("type") == "MemoryPressure"
                and cond.get("status") == "True"
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
                f"pod:{pod_name}": [
                    "Pod scheduled on node reporting MemoryPressure"
                ],
            },
            "likely_causes": [
                "Node memory exhaustion",
                "High container memory consumption",
                "System daemons consuming node memory",
                "Memory leak in co-located workload",
            ],
            "suggested_checks": [
                f"kubectl describe node {pressured_nodes[0]}"
                if pressured_nodes
                else "kubectl describe node <node>",
                f"kubectl describe pod {pod_name}",
                "Check node memory usage (free -m)",
                "Inspect container memory limits and requests",
                "Consider scaling workload or draining node",
            ],
        }


class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"
    priority = 20
    category = "Node"
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running"}

    # Node health dominates scheduler errors
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        for node in node_objs.values():
            conditions = node.get("status", {}).get("conditions", [])
            for cond in conditions:
                if cond.get("type") == "DiskPressure" and cond.get("status") == "True":
                    return True
        return False

    def explain(self, pod, events, context):
        node = next(iter(context["objects"]["node"].values()))
        node_name = node.get("metadata", {}).get("name", "unknown-node")

        return {
            "root_cause": "Node has disk pressure",
            "confidence": 0.9,
            "evidence": ["Node reported disk pressure"],
            "object_evidence": {
                f"node:{node_name}": ["NodeHasDiskPressure event observed"]
            },
            "likely_causes": [
                "Node disk is full",
                "Image or log cleanup not keeping up",
            ],
            "suggested_checks": [
                "kubectl describe node <node>",
                "Check node disk usage",
            ],
        }


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
                cond.get("type") == "PIDPressure"
                and cond.get("status") == "True"
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
                cond.get("type") == "PIDPressure"
                and cond.get("status") == "True"
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
                f"pod:{pod_name}": [
                    "Pod scheduled on node reporting PIDPressure"
                ],
            },
            "likely_causes": [
                "Process ID exhaustion on node",
                "Excessive fork/exec activity",
                "Zombie processes not reaped",
                "Workload spawning uncontrolled child processes",
            ],
            "suggested_checks": [
                f"kubectl describe node {pressured_nodes[0]}"
                if pressured_nodes
                else "kubectl describe node <node>",
                f"kubectl describe pod {pod_name}",
                "Check process count on node (ps aux | wc -l)",
                "Inspect kubelet logs for PID pressure warnings",
                "Consider restarting offending workloads",
            ],
        }
