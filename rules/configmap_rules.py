from rules.base_rule import FailureRule
from explain_failure import get_pod_name, get_pod_phase, has_event

class ConfigMapNotFoundRule(FailureRule):
    name = "ConfigMapNotFound"
    priority = 30

    def matches(self, pod, events, context):
        return any(
            e.get("reason") == "CreateContainerConfigError"
            and "configmap" in e.get("message", "").lower()
            for e in events
        )

    def explain(self, pod, events, context):
        return {
            "root_cause": "Referenced ConfigMap does not exist",
            "evidence": ["CreateContainerConfigError mentions ConfigMap"],
            "likely_causes": [
                "ConfigMap name typo",
                "ConfigMap deleted or never created",
            ],
            "suggested_checks": [
                "kubectl get configmap",
                "kubectl describe pod <name>",
            ],
            "confidence": 0.94,
        }
