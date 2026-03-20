from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline, timeline_has_event


class PodTopologySpreadLabelMismatchRule(FailureRule):
    """
    Detects Pods failing scheduling due to topologySpreadConstraints
    where node labels do not match the Pod's required topology.

    Signals:
    - FailedScheduling events with reason "TopologySpreadConstraint"
    - Pod cannot be placed due to missing or mismatched node labels
    """

    name = "PodTopologySpreadLabelMismatch"
    category = "Scheduling"
    priority = 85
    deterministic = True
    requires = {"pod": True, "context": ["objects", "timeline"]}

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline") or build_timeline(events)
        # Look for FailedScheduling events mentioning topology spread
        return timeline_has_event(
            timeline, kind="Scheduling", phase="Failure", source="kube-scheduler"
        ) and any(
            "TopologySpreadConstraint" in (e.get("message") or "") for e in events
        )

    def explain(self, pod: dict, events: list[dict], context: dict) -> dict:
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        node_labels = context.get("objects", {}).get("node", {})
        nodes_checked = []
        for node_name, node in node_labels.items():
            topology_labels = node.get("metadata", {}).get("labels", {})
            if not topology_labels:
                nodes_checked.append(node_name)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_TOPOLOGY_SPREAD",
                    message=f"Pod '{pod_name}' cannot be scheduled due to topologySpreadConstraints",
                    role="workload_context",
                ),
                Cause(
                    code="NODE_LABEL_MISMATCH",
                    message=f"Nodes {nodes_checked or '<unknown>'} do not satisfy required topology labels",
                    role="configuration_root",
                ),
                Cause(
                    code="TOPOLOGY_SPREAD_LABEL_MISMATCH",
                    message="Pod's topologySpreadConstraints labels do not match node labels",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_TOPOLOGY",
                    message="Pod cannot be scheduled due to topologySpreadConstraint label mismatch",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "TopologySpreadConstraint mismatch",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                e.get("message", "")
                for e in events
                if e.get("reason") == "FailedScheduling"
            ],
            "likely_causes": [
                "Pod topologySpreadConstraints not satisfied by available nodes",
                "Node labels missing or misconfigured",
            ],
            "suggested_checks": [
                "Verify node labels match pod's topologySpreadConstraints",
                "Check Pod's topologySpreadConstraints configuration",
                "Ensure cluster has sufficient nodes with matching labels",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": ["FailedScheduling events due to topologySpread"]
            },
        }
