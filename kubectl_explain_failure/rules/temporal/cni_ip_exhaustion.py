from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class CNIIPExhaustionRule(FailureRule):
    """
    Detects CNI plugin failures where no more IPs are available for Pods on a node.

    Signals:
    - Events with reason "CNIPluginFailure"
    - Multiple Pods failing scheduling or networking on the same node
    - No available IPs

    Interpretation:
    The node has exhausted its available IPs. Pod networking fails
    due to lack of addresses. This is usually caused by limited CNI
    IP pool or misconfigured network plugin.

    Scope:
    - Networking / CNI layer
    - Temporal / event-driven
    - Applies to multiple Pods on same node

    Exclusions:
    - Does not include DNS-only failures
    - Does not include container runtime errors unrelated to CNI
    """

    name = "CNIIPExhaustion"
    category = "Temporal"
    priority = 50
    requires = {"context": ["timeline"], "objects": ["node"]}
    deterministic = True
    blocks = ["CNIPluginFailure"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # At least one CNIPluginFailure event
        if not timeline_has_event(timeline, kind="Networking", phase="Failure", source="cni"):
            return False

        # Optional: check multiple pods failing on the same node
        node_name = pod.get("spec", {}).get("nodeName")
        if not node_name:
            return False

        node_events = [
            e for e in timeline.events
            if e.get("source") == "cni" and e.get("reason") == "CNIPluginFailure" and e.get("involvedObject", {}).get("nodeName") == node_name
        ]
        return len(node_events) >= 2  # threshold: at least 2 pods affected

    def explain(self, pod, events, context):
        node_name = pod.get("spec", {}).get("nodeName", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_PRESENT",
                    message=f"Node '{node_name}' hosting Pods is detected",
                    role="workload_context",
                ),
                Cause(
                    code="CNI_IP_EXHAUSTION",
                    message="Node has exhausted available IPs for Pods",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="CNI_PLUGIN_FAILURE_SYMPTOM",
                    message="Pods cannot be scheduled or attached to network due to CNI failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CNI IP exhaustion on node",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"CNIPluginFailure events on node {node_name}",
            ],
            "object_evidence": {f"node:{node_name}": ["No available IPs"]},
            "likely_causes": [
                "CNI IP pool exhausted",
                "Misconfigured network plugin",
            ],
            "suggested_checks": [
                f"kubectl get nodes {node_name} -o yaml",
                "kubectl describe pod <pod> | grep -i cni",
            ],
            "blocking": True,
        }