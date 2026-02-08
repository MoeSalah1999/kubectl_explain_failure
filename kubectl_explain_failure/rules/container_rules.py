from kubectl_explain_failure.model import get_pod_name
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class OOMKilledRule(FailureRule):
    name = "OOMKilled"
    priority = 16

    def matches(self, pod, events, context):
        for cs in pod.get("status", {}).get("containerStatuses", []):
            last_state = cs.get("lastState", {})
            terminated = last_state.get("terminated")
            if terminated and terminated.get("reason") == "OOMKilled":
                return True
        return False

    def explain(self, pod, events, context):
        return {
            "root_cause": "Pod container was terminated due to out-of-memory",
            "evidence": ["Container was OOMKilled"],
            "likely_causes": ["Memory limits too low", "Memory spike"],
            "suggested_checks": [
                f"kubectl describe pod {get_pod_name(pod)}",
                "Check container memory limits and usage",
            ],
            "confidence": 0.9,
        }


class CrashLoopBackOffRule(FailureRule):
    name = "CrashLoopBackOff"
    priority = 15

    def matches(self, pod, events, context):
        return any(e.get("reason") == "BackOff" for e in events)

    def explain(self, pod, events, context):
        return {
            "root_cause": "Pod container is crashing (CrashLoopBackOff)",
            "evidence": [
                f"Event reason: {e.get('reason')} - {e.get('message', '')}"
                for e in events
                if e.get("reason") == "BackOff"
            ],
            "likely_causes": [
                "Application is crashing immediately after start",
                "Configuration error causing container failure",
            ],
            "suggested_checks": [
                f"kubectl logs {get_pod_name(pod)}",
                f"kubectl describe pod {get_pod_name(pod)}",
            ],
            "confidence": 0.9,
        }


class RepeatedCrashLoopRule(FailureRule):
    name = "RepeatedCrashLoop"
    priority = 14
    category = "Container"
    phases = ["Running"]

    requires = {
        "objects": [],
    }

    def matches(self, pod, events, context):
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_pattern(timeline, r"BackOff")

    def explain(self, pod, events, context):
        return {
            "root_cause": "Container is repeatedly crashing",
            "confidence": 0.9,
            "evidence": ["BackOff event occurred repeatedly"],
            "likely_causes": [
                "Application crash",
                "Invalid container command",
            ],
            "suggested_checks": [
                "kubectl logs <pod>",
                "kubectl describe pod <pod>",
            ],
        }
