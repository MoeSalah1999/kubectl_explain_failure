from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CNIPluginFailureRule(FailureRule):
    """
    Detects infra-level CNI plugin failures during Pod sandbox creation.
    Triggered by:
      - event.reason == FailedCreatePodSandBox
      - event.message contains 'CNI'
    Critical networking-level failure.
    """

    name = "CNIPluginFailure"
    category = "Networking"
    priority = 30

    requires = {"pod": True}

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            reason = e.get("reason")
            msg = (e.get("message") or "").lower()
            if reason == "FailedCreatePodSandBox" and "cni" in msg:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CNI_PLUGIN_FAILURE",
                    message="Pod sandbox creation failed due to CNI plugin error",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "CNI plugin failure prevented Pod sandbox creation",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreatePodSandBox event containing 'CNI'",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["CNI plugin error prevented Pod networking setup"]
            },
            "likely_causes": [
                "CNI plugin misconfiguration",
                "Node network misconfiguration",
                "Missing CNI binaries or permissions",
            ],
            "suggested_checks": [
                "kubectl get nodes -o wide",
                "Check node logs for kubelet/CNI errors",
                "Verify CNI plugin installation on nodes",
            ],
        }
