from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern, timeline_has_event


class ClusterResourceStarvationCascadeRule(FailureRule):
    """
    Detects cluster-wide resource starvation causing scheduler instability.

    Signals:
    - NodeMemoryPressure present on one or more nodes
    - Scheduler repeatedly failing to place Pods
    - Pods remaining Pending due to resource exhaustion

    Interpretation:
    Cluster nodes are under memory pressure, preventing the scheduler
    from successfully placing new Pods. This creates a starvation
    cascade where multiple workloads remain unschedulable.

    Scope:
    - Cross-domain (Node + Scheduler)
    - Compound pattern across multiple failure layers
    - Temporal (pattern emerges through repeated scheduling attempts)
    """

    name = "ClusterResourceStarvationCascade"
    category = "Compound"
    priority = 90

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "FailedScheduling",
        "InsufficientResources",
        "NodeMemoryPressure",
        "PendingUnschedulable",
        "SchedulingFlapping",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not node_objs:
            return False

        # -------------------------------------------------
        # Detect NodeMemoryPressure across cluster nodes
        # -------------------------------------------------
        memory_pressure_detected = False

        for node in node_objs.values():
            conditions = node.get("status", {}).get("conditions", [])

            for cond in conditions:
                if (
                    cond.get("type") == "MemoryPressure"
                    and cond.get("status") == "True"
                ):
                    memory_pressure_detected = True
                    context["memory_pressure_node"] = node.get("metadata", {}).get(
                        "name", "<node>"
                    )
                    break

        if not memory_pressure_detected:
            return False

        # -------------------------------------------------
        # Detect repeated scheduling failures
        # -------------------------------------------------
        if not timeline.repeated("FailedScheduling", 3):
            return False

        # -------------------------------------------------
        # Reinforce via structured scheduler failure signal
        # -------------------------------------------------
        if not timeline_has_event(
            timeline,
            kind="Scheduling",
            phase="Failure",
        ):
            return False

        # -------------------------------------------------
        # Optional signal: scheduling flapping
        # -------------------------------------------------
        if timeline_has_pattern(
            timeline,
            [
                {"reason": "FailedScheduling"},
                {"reason": "FailedScheduling"},
            ],
        ):
            context["scheduler_flapping"] = True

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        node_name = context.get("memory_pressure_node", "<node>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_WORKLOAD_DEMAND",
                    message="Cluster scheduling demand exceeds available capacity",
                    role="cluster_context",
                ),
                Cause(
                    code="NODE_MEMORY_PRESSURE",
                    message=f"Node '{node_name}' reports MemoryPressure",
                    role="node_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_RESOURCE_STARVATION",
                    message="Scheduler cannot place Pods due to insufficient resources",
                    role="scheduler_intermediate",
                ),
                Cause(
                    code="PODS_PENDING_CLUSTER_STARVATION",
                    message="Pods remain Pending due to cluster-wide resource starvation",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Cluster resource starvation caused by NodeMemoryPressure",
            "confidence": 0.93,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Node condition: MemoryPressure=True",
                "Repeated scheduler failures detected",
                f"Pod {pod_name} remains Pending",
            ],
            "likely_causes": [
                "Cluster nodes exhausted available memory",
                "Too many workloads scheduled on limited nodes",
                "Resource limits preventing new Pods from scheduling",
            ],
            "suggested_checks": [
                "kubectl describe nodes",
                "kubectl top nodes",
                f"kubectl describe pod {pod_name}",
            ],
            "object_evidence": {
                f"node:{node_name}": ["MemoryPressure=True detected"]
            },
        }