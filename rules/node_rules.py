from rules.base_rule import FailureRule
from explain_failure import get_pod_name, get_pod_phase, has_event

class NodeDiskPressureRule(FailureRule):
    name = "NodeDiskPressure"
    priority = 80

    def matches(self, pod, events, context):
        node_events = context.get("node")
        if not node_events:
            return False

        if node_events.get("kind") == "List":
            items = node_events.get("items", [])
        else:
            items = [node_events]

        return any(
            e.get("reason") == "NodeHasDiskPressure"
            for e in items
        )


    def explain(self, pod, events, context):
        node_events = context.get("node")
        items = node_events.get("items", []) if node_events else []

        messages = [
            e.get("message", "")
            for e in items
            if e.get("reason") == "NodeHasDiskPressure"
        ]

        return {
            "root_cause": "Node has disk pressure",
            "evidence": messages or ["Node reported disk pressure"],
            "likely_causes": [
                "Node disk is full",
                "Log or image garbage collection not keeping up",
            ],
            "suggested_checks": [
                "kubectl describe node <node-name>",
                "Check node disk usage",
            ],
            "confidence": 0.9,
        }
