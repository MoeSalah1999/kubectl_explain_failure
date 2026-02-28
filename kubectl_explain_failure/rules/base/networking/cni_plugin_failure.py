from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CNIPluginFailureRule(FailureRule):
    """
    Detects CNI plugin failures during Pod sandbox creation.

    Signals:
    - Event.reason == "FailedCreatePodSandBox"
    - Event.message contains "CNI"

    Interpretation:
    During Pod startup, the Kubelet attempts to create a sandbox and configure
    networking using the Container Network Interface (CNI) plugin. If the CNI
    plugin fails, the Pod sandbox cannot be created, preventing network
    initialization and blocking Pod startup.

    Scope:
    - Node runtime / Kubelet initialization phase
    - Deterministic (event-message based)
    - Captures infrastructure-level networking failures

    Exclusions:
    - Does not detect scheduler failures or admission rejections
    - Does not detect container runtime crashes unrelated to networking
    - Does not diagnose specific CNI implementation details
    """

    name = "CNIPluginFailure"
    category = "Networking"
    priority = 30
    deterministic = True
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
                    code="POD_SANDBOX_INITIALIZATION",
                    message="Kubelet is initializing Pod sandbox",
                    role="runtime_context",
                ),
                Cause(
                    code="CNI_PLUGIN_FAILURE",
                    message="CNI plugin failed during network setup",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_NETWORK_UNAVAILABLE",
                    message="Pod sandbox could not be created due to networking failure",
                    role="workload_symptom",
                ),
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
