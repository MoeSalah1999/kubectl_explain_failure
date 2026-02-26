from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class NodePIDPressureRule(FailureRule):
    name = "NodePIDPressure"
    category = "Node"
    priority = 19  # Same tier as other node resource pressure signals
    deterministic = True
    requires = {
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        if not node_objs:
            return False

        # --- Hard infrastructure condition ---
        pressured_nodes = [
            node
            for node in node_objs.values()
            if any(
                cond.get("type") == "PIDPressure"
                and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        if not pressured_nodes:
            return False
        
        pod_node = pod.get("spec", {}).get("nodeName")

        if pod_node:
            pressured_node_names = [
                name
                for name, node in node_objs.items()
                if any(
                    cond.get("type") == "PIDPressure"
                    and cond.get("status") == "True"
                    for cond in node.get("status", {}).get("conditions", [])
                )
            ]
            if pod_node not in pressured_node_names:
                return False

        # --- Optional temporal corroboration ---
        timeline = context.get("timeline")

        if timeline:
            # Recent scheduling failures (10 min window)
            if timeline.events_within_window(10, reason="FailedScheduling"):
                return True

            # Any structured scheduling failure
            if timeline_has_event(
                timeline,
                kind="Scheduling",
                phase="Failure",
            ):
                return True

            # Recent container instability signals
            recent = timeline.events_within_window(10)
            if any(
                (e.get("reason") or "").lower().startswith(("oom", "backoff"))
                for e in recent
            ):
                return True

        # --- PIDPressure alone is sufficient ---
        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        objects = context.get("objects", {})
        node_objs = objects.get("node", {})

        pressured_nodes = [
            name
            for name, node in node_objs.items()
            if any(
                cond.get("type") == "PIDPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PID_PRESSURE_DETECTED",
                    message=f"Node(s) reporting PIDPressure=True: {', '.join(pressured_nodes)}",
                    role="infrastructure_root",
                ),
                Cause(
                    code="NODE_PROCESS_TABLE_EXHAUSTION",
                    message="Node process table resources are under pressure",
                    blocking=True,
                    role="resource_root",
                ),
                Cause(
                    code="POD_RUNTIME_OR_SCHEDULING_IMPACT",
                    message="Pod affected by node PID resource constraints",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod affected by Node PIDPressure condition",
            "confidence": 0.90,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Node condition PIDPressure=True detected",
            ],
            "object_evidence": {
                **{
                    f"node:{name}": ["Node condition PIDPressure=True"]
                    for name in pressured_nodes
                },
                f"pod:{pod_name}": ["Pod scheduled on node reporting PIDPressure"],
            },
            "likely_causes": [
                "Process ID exhaustion on node",
                "Excessive fork/exec activity",
                "Zombie processes not reaped",
                "Workload spawning uncontrolled child processes",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {pressured_nodes[0]}"
                    if pressured_nodes
                    else "kubectl describe node <node>"
                ),
                f"kubectl describe pod {pod_name}",
                "Check process count on node (ps aux | wc -l)",
                "Inspect kubelet logs for PID pressure warnings",
                "Consider restarting offending workloads",
            ],
        }
