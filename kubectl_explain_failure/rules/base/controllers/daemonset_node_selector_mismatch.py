from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class DaemonSetNodeSelectorMismatchRule(FailureRule):
    """
    Detects DaemonSet Pods failing to schedule due to node label changes.

    Signals:
    - Pod owned by a DaemonSet
    - Timeline contains FailedScheduling events
    - Node labels changed, preventing Pod placement

    Interpretation:
    The DaemonSet intended to run on certain nodes cannot schedule Pods because
    the target node labels no longer match the nodeSelector defined in the DaemonSet.
    This leaves Pods in Pending state.

    Scope:
    - Controller-level (DaemonSet)
    - Deterministic (event + object-based)
    - Applies to Pods managed by DaemonSets
    """

    name = "DaemonSetNodeSelectorMismatch"
    category = "Controller"
    priority = 40
    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }
    deterministic = True
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        owners = pod.get("metadata", {}).get("ownerReferences", [])
        is_daemonset = any(o.get("kind") == "DaemonSet" for o in owners)

        if not is_daemonset or not timeline:
            return False

        # Look for repeated FailedScheduling events
        return timeline_has_event(timeline, kind="Scheduling", phase="Failure")

    def explain(self, pod, events, context):
        node_objs = context.get("objects", {}).get("node", {})
        timeline = context.get("timeline")

        owners = pod.get("metadata", {}).get("ownerReferences", [])
        ds_owner = next((o for o in owners if o.get("kind") == "DaemonSet"), {})
        ds_name = ds_owner.get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="DAEMONSET_PRESENT",
                    message=f"Pod is managed by DaemonSet '{ds_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="NODE_SELECTOR_MISMATCH",
                    message="Node labels changed and no longer match DaemonSet nodeSelector",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="FAILED_SCHEDULING",
                    message="Pod cannot be scheduled onto any node",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "DaemonSet nodeSelector mismatch",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"DaemonSet: {ds_name}",
                "FailedScheduling events in timeline",
            ],
            "object_evidence": {f"pod:{pod.get('metadata', {}).get('name', '<pod>')}": ["DaemonSet nodeSelector mismatch"]},
            "likely_causes": [
                "Node labels modified after DaemonSet creation",
                "DaemonSet nodeSelector incompatible with existing nodes",
            ],
            "suggested_checks": [
                f"kubectl describe ds {ds_name}",
                "kubectl get nodes --show-labels",
                f"kubectl describe pod {pod.get('metadata', {}).get('name', '<pod>')}",
            ],
            "blocking": True,
        }