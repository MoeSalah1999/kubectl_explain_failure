from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


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


class InsufficientResourcesRule(FailureRule):
    """
    Detects pod scheduling failures due to insufficient CPU, memory, or ephemeral storage.
    Object-first: checks structured scheduler status.
    """
    name = "InsufficientResources"
    category = "Node"
    priority = 15  # Align with other node scheduling signals

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline", [])
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not timeline or not node_objs:
            return False

        # Check FailedScheduling events with Insufficient resource reasons
        insufficient_pattern = [
            {"reason": "FailedScheduling", "message": "Insufficient"}
        ]
        return timeline_has_pattern(timeline, insufficient_pattern)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        objects = context.get("objects", {})
        node_names = list(objects.get("node", {}).keys())

        # Compose causal chain
        chain = CausalChain(
            causes=[
                Cause(
                    code="INSUFFICIENT_RESOURCES",
                    message=f"Pod failed scheduling due to insufficient CPU/memory/ephemeral-storage on node(s): {', '.join(node_names)}",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod failed scheduling due to insufficient resources",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedScheduling events with Insufficient CPU/Memory/EphemeralStorage detected",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod could not be scheduled due to resource insufficiency"
                ],
                **{f"node:{name}": ["Node could not satisfy resource requests"] for name in node_names},
            },
            "likely_causes": [
                "Cluster nodes lack sufficient CPU cores or memory",
                "Pods requesting ephemeral storage beyond node capacity",
                "Other workloads consuming node resources",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes to check allocatable resources",
                "Consider scaling the cluster or reducing pod resource requests",
            ],
        }
    

class NodeSelectorMismatchRule(FailureRule):
    """
    Detects scheduling failures when Pod.spec.nodeSelector cannot match any node labels.
    High-signal object-first scheduling failure.
    """
    name = "NodeSelectorMismatch"
    category = "Node"
    priority = 16

    requires = {
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        pod_spec = pod.get("spec", {})
        node_selector = pod_spec.get("nodeSelector", {})
        node_objs = context.get("objects", {}).get("node", {})

        if not node_selector or not node_objs:
            return False

        # Check if any node satisfies all nodeSelector labels
        for node in node_objs.values():
            labels = node.get("metadata", {}).get("labels", {})
            if all(labels.get(k) == v for k, v in node_selector.items()):
                return False  # At least one match found

        # No matching nodes
        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_selector = pod.get("spec", {}).get("nodeSelector", {})
        node_objs = context.get("objects", {}).get("node", {})
        node_names = list(node_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_SELECTOR_MISMATCH",
                    message=f"No nodes match Pod.nodeSelector: {node_selector}",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod nodeSelector does not match any node labels",
            "confidence": 0.92,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod has nodeSelector {node_selector}, but no nodes satisfy all labels"
            ],
            "object_evidence": {
                f"pod:{pod_name}": [f"Pod nodeSelector {node_selector} mismatch"],
                **{f"node:{name}": ["Node labels do not satisfy Pod nodeSelector"] for name in node_names},
            },
            "likely_causes": [
                "NodeSelector specifies labels not present on any node",
                "Cluster labels misconfigured",
                "Pod scheduling constraints too strict",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Adjust pod nodeSelector or add matching labels to nodes",
            ],
        }