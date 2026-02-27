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

        pod_phase = pod.get("status", {}).get("phase")
        timeline = context.get("timeline")

        impact_detected = False

        if timeline:
            recent_events = timeline.events_within_window(10)

            for e in recent_events:
                reason = (e.get("reason") or "").lower()
                if reason.startswith(("failedscheduling", "backoff", "oom")):
                    impact_detected = True
                    break

        causes = [
            Cause(
                code="NODE_PID_PRESSURE",
                message=f"Node(s) reporting PIDPressure=True: {', '.join(pressured_nodes)}",
                role="infrastructure_root",
            )
        ]

        if impact_detected:
            causes.append(
                Cause(
                    code="CONTROL_PLANE_OR_RUNTIME_IMPACT",
                    message="Scheduler or runtime impacted by PID resource constraints",
                    role="control_plane_effect",
                )
            )

        if pod_phase in {"Pending", "Failed"} or impact_detected:
            causes.append(
                Cause(
                    code="POD_IMPACTED_BY_PID_PRESSURE",
                    message="Pod affected by node PID pressure",
                    blocking=True,
                    role="workload_symptom",
                )
            )

        chain = CausalChain(causes=causes)

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
