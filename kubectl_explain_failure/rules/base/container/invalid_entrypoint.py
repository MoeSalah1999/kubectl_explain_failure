
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InvalidEntrypointRule(FailureRule):
    """
    Detects containers failing due to invalid entrypoint.
    Triggered when container state.waiting.reason=RunContainerError
    """
    name = "InvalidEntrypoint"
    category = "Container"
    priority = 22
    blocks = ["CrashLoopBackOff"]
    container_states = ["waiting"]
    phases = ["Pending", "Running"]

    def matches(self, pod, events, context) -> bool:
        for c in pod.get("status", {}).get("containerStatuses", []):
            waiting = c.get("state", {}).get("waiting")
            if waiting and waiting.get("reason") == "RunContainerError":
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="INVALID_ENTRYPOINT",
                    message="Container failed due to invalid entrypoint",
                    blocking=True
                )
            ]
        )
        return {
            "rule": self.name,
            "root_cause": "Container failed due to invalid entrypoint",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Container state.waiting.reason=RunContainerError",
                f"Pod: {pod_name}"
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["RunContainerError observed"]
            },
            "likely_causes": [
                "Command or args in container spec are invalid",
                "Entrypoint binary missing or incorrect"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review container command and args"
            ]
        }
