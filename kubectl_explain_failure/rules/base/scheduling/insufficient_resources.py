from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InsufficientResourcesRule(FailureRule):
    """
    Detects pod scheduling failures due to insufficient CPU, memory, or ephemeral storage.
    Object-first: checks structured scheduler status.
    """

    name = "InsufficientResources"
    category = "Scheduling"
    priority = 8

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline", [])
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not timeline or not node_objs:
            return False

        # Check FailedScheduling events with Insufficient resource reasons
        for ev in timeline.events:
            reason = ev.get("reason", "")
            message = ev.get("message", "")
            if reason == "FailedScheduling" and "Insufficient" in message:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        objects = context.get("objects", {})
        node_names = list(objects.get("node", {}).keys())

        # Compose causal chain
        chain = CausalChain(
            causes=[
                Cause(
                    code="INSUFFICIENT_RESOURCES",
                    message=f"Pod failed scheduling due to insufficient CPU/memory/ephemeral-storage on node(s): {', '.join(node_names)}",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod failed scheduling due to insufficient resources",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedScheduling events with Insufficient CPU/Memory/EphemeralStorage detected",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod could not be scheduled due to resource insufficiency"
                ],
                **{
                    f"node:{name}": ["Node could not satisfy resource requests"]
                    for name in node_names
                },
            },
            "likely_causes": [
                "Cluster nodes lack sufficient CPU cores or memory",
                "Pods requesting ephemeral storage beyond node capacity",
                "Other workloads consuming node resources",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes to check allocatable resources",
                "Consider scaling the cluster or reducing pod resource requests",
            ],
        }
