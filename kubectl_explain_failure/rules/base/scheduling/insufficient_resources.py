from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InsufficientResourcesRule(FailureRule):
    """
    Detects Pod scheduling failures caused by insufficient cluster resources.

    Signals:
    - Timeline contains 'FailedScheduling' events with "Insufficient" resource messages
    - Scheduler reports inability to place Pod due to resource constraints

    Interpretation:
    The Pod specifies CPU, memory, or ephemeral storage requests that cannot 
    be satisfied by any available node in the cluster. The scheduler fails 
    placement, leaving the Pod in a Pending state.

    Scope:
    - Scheduler phase
    - Deterministic (event-based)
    - Captures infrastructure-level resource exhaustion

    Exclusions:
    - Does not include taint/toleration mismatches
    - Does not include node affinity or topology constraints
    - Does not include image pull or runtime failures
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
                    code="POD_RESOURCE_REQUEST_DEFINED",
                    message="Pod declares CPU/memory/ephemeral-storage resource requests",
                    role="workload_context",
                ),
                Cause(
                    code="SCHEDULER_INSUFFICIENT_CAPACITY",
                    message="Kubernetes scheduler found no node with sufficient allocatable resources",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SCHEDULING_FAILED",
                    message=f"Pod remains Pending due to insufficient resources on node(s): {', '.join(node_names)}",
                    role="scheduler_symptom",
                ),
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
