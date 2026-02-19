from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class UnschedulableTaintRule(FailureRule):
    """
    Detects scheduling failure due to node taints not tolerated by the Pod.
    Triggered by FailedScheduling events referencing taints.
    """

    name = "UnschedulableTaint"
    category = "Scheduling"
    priority = 85
    blocks = ["FailedScheduling"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        entries = getattr(timeline, "events", [])

        for entry in entries:
            reason = str(entry.get("reason", "")).lower()
            message = str(entry.get("message", "")).lower()

            if reason == "failedscheduling" and (
                "taint" in message
                or "didn't tolerate" in message
                or "had taint" in message
                or "node(s) had taint" in message
            ):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="UNSCHEDULABLE_TAINT",
                    message="Pod does not tolerate required node taints",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Scheduling failed due to untolerated node taints",
            "confidence": 0.94,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedScheduling event detected",
                "Event message references node taints or missing tolerations",
            ],
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    "FailedScheduling event",
                    "Message contains taint intolerance indication",
                ]
            },
            "likely_causes": [
                "Pod missing required tolerations",
                "Node taints restrict scheduling",
                "Cluster-wide taints prevent placement",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl describe nodes",
                "Verify pod tolerations match node taints",
            ],
        }
