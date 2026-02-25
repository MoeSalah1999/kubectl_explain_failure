from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ContainerCreateConfigErrorRule(FailureRule):
    """
    Detects containers failing due to CreateContainerConfigError.
    Triggered when container state.waiting.reason=CreateContainerConfigError
    """

    name = "ContainerCreateConfigError"
    category = "Container"
    priority = 25
    blocks = ["CrashLoopBackOff"]
    container_states = ["waiting"]
    phases = ["Pending", "Running"]

    def matches(self, pod, events, context) -> bool:
        for c in pod.get("status", {}).get("containerStatuses", []):
            waiting = c.get("state", {}).get("waiting")
            if waiting and waiting.get("reason") == "CreateContainerConfigError":
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        
        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_CONFIG_INVALID",
                    message="Container specification is invalid or references missing configuration",
                    role="configuration_root",
                ),
                Cause(
                    code="CREATE_CONTAINER_CONFIG_ERROR",
                    message="Kubelet reports CreateContainerConfigError",
                    blocking=True,
                    role="runtime_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container failed due to CreateContainerConfigError",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Container state.waiting.reason=CreateContainerConfigError",
                f"Pod: {pod_name}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["CreateContainerConfigError observed"]
            },
            "likely_causes": [
                "Invalid container spec",
                "Incorrect environment variables",
                "Missing secrets or configmaps",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review container spec for invalid config",
            ],
        }
