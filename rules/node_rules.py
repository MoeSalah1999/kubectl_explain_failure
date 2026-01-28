from explain_failure import FailureRule

class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"

    def matches(self, pod, events, context):
        node = context.get("node")
        if not node:
            return False
        conditions = node.get("status", {}).get("conditions", [])
        return any(
            c.get("type") == "DiskPressure" and c.get("status") == "True"
            for c in conditions
        )

    def explain(self, pod, events, context):
        return {
            "root_cause": "Node is under disk pressure",
            "evidence": ["Node condition DiskPressure=True"],
            "likely_causes": [
                "Node disk is full",
                "Log or image garbage collection not keeping up",
            ],
            "suggested_checks": [
                "kubectl describe node <name>",
                "Check node disk usage",
            ],
            "confidence": 0.93,
        }
