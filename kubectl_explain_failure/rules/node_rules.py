from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"
    priority = 80
    category = "Node"
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running"}

    # Node health dominates scheduler errors
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context):
        # Primary signal: explicit events
        if any(
            e.get("reason") in ("NodeHasDiskPressure", "NodeDiskPressure")
            for e in events
        ):
            return True

        # Legacy compatibility: node context may actually be an event list
        node_objs = context.get("objects", {}).get("node", {})
        for node in node_objs.values():
            if node.get("kind") == "List":
                for item in node.get("items", []):
                    if item.get("reason") == "NodeHasDiskPressure":
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
