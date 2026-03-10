from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class NodeUnschedulableCordonedRule(FailureRule):
    """
    Detects scheduling failures caused by nodes being cordoned (unschedulable).

    Signals:
    - Node.spec.unschedulable == True
    - Scheduler emits FailedScheduling events

    Interpretation:
    The scheduler attempted to place the Pod but available nodes were
    marked unschedulable (cordoned), preventing new Pods from being scheduled.

    Scope:
    - Scheduler-level failure
    - Deterministic when node unschedulable state is present
    """

    name = "NodeUnschedulableCordoned"
    category = "Scheduling"
    priority = 17
    deterministic = True

    requires = {
        "pod": True,
        "objects": ["node"],
    }

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        # Detect any cordoned nodes
        cordoned_nodes = [
            name
            for name, node in node_objs.items()
            if node.get("spec", {}).get("unschedulable") is True
        ]

        if not cordoned_nodes:
            return False

        timeline = build_timeline(events)

        # Scheduler must have attempted scheduling
        failed_sched = timeline.events_within_window(
            15,
            reason="FailedScheduling",
        )

        if not failed_sched:
            return False

        # Look for unschedulable hints in scheduler message
        for e in failed_sched:
            msg = (e.get("message") or "").lower()
            if "unschedulable" in msg or "node(s) were unschedulable" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})

        cordoned_nodes = [
            name
            for name, node in node_objs.items()
            if node.get("spec", {}).get("unschedulable") is True
        ]

        timeline = build_timeline(events)

        failed_sched = timeline.events_within_window(
            15,
            reason="FailedScheduling",
        )

        evidence_msgs = []

        for e in failed_sched:
            msg = e.get("message")
            if not msg:
                continue
            if "unschedulable" in msg.lower():
                evidence_msgs.append(msg)

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_CORDONED",
                    message="Node marked unschedulable (cordoned)",
                    role="scheduler_context",
                ),
                Cause(
                    code="NODE_UNSCHEDULABLE",
                    message="Scheduler cannot place Pod on cordoned nodes",
                    role="scheduler_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_NO_SCHEDULABLE_NODE",
                    message="Pod remains pending because nodes are unschedulable",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        return {
            "rule": self.name,
            "root_cause": "Nodes are cordoned (unschedulable) preventing scheduling",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"{len(cordoned_nodes)} node(s) marked unschedulable",
                f"Cordoned nodes: {', '.join(cordoned_nodes)}",
                f"{len(failed_sched)} FailedScheduling events observed",
                *evidence_msgs[:2],
            ],
            "object_evidence": {
                f"node:{name}": ["Node.spec.unschedulable=True"]
                for name in cordoned_nodes
            },
            "likely_causes": [
                "Cluster maintenance operation",
                "Node intentionally cordoned with kubectl cordon",
                "Cluster autoscaler temporarily cordoned nodes",
            ],
            "suggested_checks": [
                "kubectl get nodes",
                "kubectl describe node",
                "kubectl get nodes -o wide",
                "kubectl uncordon <node-name>",
            ],
        }