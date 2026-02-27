from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class EvictedRule(FailureRule):
    """
    Detects Pod eviction events triggered by the Kubelet.

    Signals:
    - Timeline contains an event with reason "Evicted"
    - Pod phase transitions to "Failed"

    Interpretation:
    The Kubelet eviction manager terminated the Pod due to node-level
    resource pressure (e.g., memory, disk, or PID exhaustion).
    The Pod is forcibly removed from the node and cannot continue running.

    Scope:
    - Node-level resource management
    - Deterministic (event-based)
    - Captures Kubelet-initiated eviction decisions

    Exclusions:
    - Does not diagnose the specific resource threshold exceeded
    - Does not detect NodeNotReady conditions (handled by compound rules)
    - Does not model scheduler rescheduling behavior
    """
    name = "Evicted"
    category = "Node"
    priority = 21  # Lower than compound rules like NodeNotReadyEvicted
    phases = ["Failed"]
    requires = {
        "context": ["timeline"],
    }
    deterministic = True

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Eviction is a raw reason emitted by kubelet
        return timeline.count(reason="Evicted") > 0
    
    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = pod.get("spec", {}).get("nodeName", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_RESOURCE_PRESSURE",
                    message="Node reports resource pressure (memory, disk, or PID)",
                    role="infrastructure_context",
                ),
                Cause(
                    code="KUBELET_EVICTION_MANAGER",
                    message="Kubelet eviction manager selected Pod for eviction",
                    role="infrastructure_root",
                ),
                Cause(
                    code="POD_EVICTED",
                    message="Pod was evicted from node",
                    blocking=True,
                    role="workload_termination",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod was evicted from node",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Event: Evicted",
                f"Pod {pod_name} entered Failed phase",
            ],
            "object_evidence": {f"pod:{pod_name}": [f"Evicted from node {node_name}"]},
            "likely_causes": [
                "Node memory pressure",
                "Node disk pressure",
                "Node PID exhaustion",
                "Resource limits exceeded relative to QoS class",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe node {node_name}",
                "Check node conditions (MemoryPressure, DiskPressure)",
                "Review Pod QoS class and resource requests/limits",
            ],
            "blocking": True,
        }
