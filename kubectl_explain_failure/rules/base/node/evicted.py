from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule


class EvictedRule(FailureRule):
    name = "Evicted"
    category = "Node"
    priority = 21  # Lower than compound rules like NodeNotReadyEvicted
    phases = ["Failed"]

    def matches(self, pod, events, context) -> bool:
        # Match Kubernetes eviction signal
        return has_event(events, "Evicted")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = pod.get("spec", {}).get("nodeName", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_EVICTED",
                    message="Pod was evicted from node",
                    blocking=True,
                )
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
                "Node resource exhaustion",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe node {node_name}",
                "Check node conditions (MemoryPressure, DiskPressure)",
            ],
            "blocking": True,
        }
