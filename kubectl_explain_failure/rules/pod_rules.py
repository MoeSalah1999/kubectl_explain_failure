from kubectl_explain_failure.model import get_pod_phase, has_event, pod_condition
from kubectl_explain_failure.rules.base_rule import FailureRule


class FailedSchedulingRule(FailureRule):
    name = "FailedScheduling"
    priority = 90

    def matches(self, pod, events, context):
        cond = pod_condition(pod, "PodScheduled")
        if cond and cond.get("status") == "False":
            return True
        return has_event(events, "FailedScheduling")

    def explain(self, pod, events, context):
        return {
            "root_cause": "Pod could not be scheduled",
            "evidence": ["Event: FailedScheduling"],
            "object_evidence": {
                f"pod:{pod.get('metadata', {}).get('name')}": [
                    "Scheduler could not place pod"
                ]
            },
            "likely_causes": [
                "No nodes satisfy resource requests",
                "Node taints or affinity rules prevent scheduling",
                "Cluster autoscaling is disabled or blocked",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get nodes",
                "kubectl get events",
            ],
            "confidence": 0.90,
        }


class FailedMountRule(FailureRule):
    name = "FailedMount"
    priority = 20

    def matches(self, pod, events, context):
        return has_event(events, "FailedMount")

    def explain(self, pod, events, context):
        return {
            "root_cause": "Volume could not be mounted",
            "evidence": ["Event: FailedMount"],
            "likely_causes": [
                "PersistentVolumeClaim not bound",
                "Storage backend unavailable",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get pvc",
            ],
            "confidence": 0.85,
        }


class UnschedulableTaintRule(FailureRule):
    name = "UnschedulableTaint"
    priority = 100

    def matches(self, pod, events, context):
        return has_event(events, "FailedScheduling") and any(
            "taint" in e.get("message", "").lower() for e in events
        )

    def explain(self, pod, events, context):
        return {
            "root_cause": "Pod cannot tolerate node taints",
            "evidence": ["FailedScheduling mentions taints"],
            "likely_causes": [
                "Pod lacks required tolerations",
                "Node taints block all eligible nodes",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl describe nodes",
            ],
            "confidence": 0.92,
        }
