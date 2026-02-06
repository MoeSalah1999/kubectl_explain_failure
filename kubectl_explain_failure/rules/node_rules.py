from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"
    priority = 80
    category = "Node"
    requires = {
        "objects": ["node"],
    }

    # Node health dominates scheduler errors
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context):
        conditions = context.get("node_conditions", {})
        return conditions.get("DiskPressure") == "True"

    def explain(self, pod, events, context):
        node = context["node"]
        node_name = node["metadata"]["name"]

        return {
            "root_cause": "Node has disk pressure",
            "confidence": 0.9,
            "evidence": ["Node condition DiskPressure=True"],
            "object_evidence": {
                f"node:{node_name}": ["DiskPressure condition is True"]
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
