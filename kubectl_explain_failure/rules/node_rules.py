from kubectl_explain_failure.rules.base_rule import FailureRule


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
