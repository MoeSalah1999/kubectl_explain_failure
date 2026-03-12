from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class CrashLoopAfterNodeDrainRule(FailureRule):
    """
    Detects Pods that begin CrashLoopBackOff after being rescheduled
    due to a node drain or cordon operation.

    Pattern:
    - Node becomes unschedulable or drained
    - Pod is rescheduled onto another node
    - Container enters CrashLoopBackOff

    Interpretation:
    The workload likely depends on node-specific configuration
    (filesystem, hostPath, kernel modules, device plugins, etc.).
    After being rescheduled to a different node, the dependency
    is missing and the container repeatedly crashes.

    Scope:
    - Cross-domain compound rule
    - Uses timeline event ordering
    """

    name = "CrashLoopAfterNodeDrain"
    category = "Compound"
    priority = 85
    deterministic = True

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
        "NodeUnschedulableCordoned",
        "EvictedRule",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Pattern:
        # node drain/cordon → scheduling → CrashLoop
        return timeline_has_pattern(
            timeline,
            [
                {"reason": "NodeNotReady"},
                {"reason": "Scheduled"},
                {"reason": "BackOff"},
            ],
        )

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        node_name = next(iter(node_objs), "<unknown>")
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_DRAINED",
                    message=f"Node '{node_name}' became unavailable or was drained",
                    role="node_context",
                ),
                Cause(
                    code="POD_RESCHEDULED",
                    message="Pod was rescheduled onto a different node",
                    role="scheduling_transition",
                ),
                Cause(
                    code="NODE_DEPENDENCY_MISSING",
                    message="New node lacks configuration required by the workload",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="CRASHLOOP_BACKOFF",
                    message="Container repeatedly crashes after rescheduling",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod crashes after node drain due to node-specific dependency",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} restarted after node drain",
                "Timeline shows scheduling followed by CrashLoopBackOff",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    "Node became unavailable or drained before crash loop"
                ]
            },
            "likely_causes": [
                "hostPath dependency missing on new node",
                "device plugin unavailable on target node",
                "kernel module or filesystem missing",
                "node-specific configuration required by container",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get pod {pod_name} -o wide",
                "Verify hostPath mounts or node-specific dependencies",
                "Check node labels and node selectors",
            ],
            "blocking": False,
        }