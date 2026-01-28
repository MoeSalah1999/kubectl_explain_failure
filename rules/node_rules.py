from rules.base_rule import FailureRule
from explain_failure import get_pod_name, get_pod_phase, has_event

class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"
    priority = 80

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
