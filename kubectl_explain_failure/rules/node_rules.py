from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class EvictedRule(FailureRule):
    name = "Evicted"
    category = "Node"
    priority = 40  # Lower than compound rules like NodeNotReadyEvicted
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
