from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class NodeMemoryPressureRule(FailureRule):
    """
    Detects node-level memory pressure impacting Pod scheduling or runtime stability.

    Signals:
    - Node.status.conditions[type="MemoryPressure"].status == "True"
    - Optional correlation with recent FailedScheduling, OOM, or BackOff events

    Interpretation:
    A node reports MemoryPressure=True, indicating insufficient available
    memory resources. Under memory pressure, the scheduler may be unable
    to place new Pods, or existing Pods may experience eviction,
    OOM termination, or runtime instability.

    Scope:
    - Node infrastructure condition
    - Deterministic (node state with optional event correlation)
    - Captures scheduler and workload impact caused by memory exhaustion

    Exclusions:
    - Does not compute allocatable vs requested memory
    - Does not inspect cgroup or container memory statistics
    - Does not model kubelet eviction thresholds explicitly
    - Does not diagnose application-level memory leaks
    """
    name = "NodeMemoryPressure"
    category = "Node"
    priority = 22  # Same tier as DiskPressure-level node signals
    deterministic = True
    requires = {
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not node_objs:
            return False

        # --- Check MemoryPressure condition ---
        pressured_nodes = [
            node
            for node in node_objs.values()
            if any(
                cond.get("type") == "MemoryPressure"
                and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        if not pressured_nodes:
            return False

        # --- Correlate with recent failure signals ---
        timeline = context.get("timeline")

        if timeline:
            # Recent scheduling failures (10 minute window)
            recent_sched = timeline.events_within_window(
                10,
                reason="FailedScheduling",
            )

            if recent_sched:
                return True

            # Any structured scheduling failure
            if timeline_has_event(
                timeline,
                kind="Scheduling",
                phase="Failure",
            ):
                return True

            # Recent OOM or BackOff events (container pressure spillover)
            recent_failures = timeline.events_within_window(10)

            if any(
                (e.get("reason") or "").lower().startswith(("oom", "backoff"))
                for e in recent_failures
            ):
                return True

        # If no correlation signals matched,
        # MemoryPressure alone is sufficient to explain impact
        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        pressured_nodes = [
            name
            for name, node in node_objs.items()
            if any(
                cond.get("type") == "MemoryPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]
        pod_phase = pod.get("status", {}).get("phase")
        timeline = context.get("timeline")

        impact_detected = False
        if timeline:
            recent_events = timeline.events_within_window(10)
            for e in recent_events:
                reason = (e.get("reason") or "").lower()
                if reason.startswith(("oom", "backoff", "failedscheduling")):
                    impact_detected = True
                    break

        causes = [
            Cause(
                code="NODE_MEMORY_PRESSURE",
                message=f"Node(s) reporting MemoryPressure=True: {', '.join(pressured_nodes)}",
                role="infrastructure_root",
                blocking=True,
            )
        ]

        if impact_detected:
            causes.append(
                Cause(
                    code="CONTROL_PLANE_OR_RUNTIME_IMPACT",
                    message="Scheduler or runtime impacted by node memory constraints",
                    role="control_plane_effect",
                )
            )

        if pod_phase in {"Pending", "Failed"} or impact_detected:
            causes.append(
                Cause(
                    code="POD_IMPACTED_BY_MEMORY_PRESSURE",
                    message="Pod affected by node memory pressure",
                    role="workload_symptom",
                )
            )

        chain = CausalChain(causes=causes)

        return {
            "rule": self.name,
            "root_cause": "Pod affected by Node MemoryPressure condition",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Node condition MemoryPressure=True detected",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": ["Node condition MemoryPressure=True"]
                    for name in pressured_nodes
                },
                f"pod:{pod_name}": ["Pod scheduled on node reporting MemoryPressure"],
            },
            "likely_causes": [
                "Node memory exhaustion",
                "High container memory consumption",
                "System daemons consuming node memory",
                "Memory leak in co-located workload",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {pressured_nodes[0]}"
                    if pressured_nodes
                    else "kubectl describe node <node>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check node memory usage (free -m)",
                "Inspect container memory limits and requests",
                "Consider scaling workload or draining node",
            ],
        }
