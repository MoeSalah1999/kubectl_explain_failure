from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InitContainerBlocksMainRule(FailureRule):
    """
    Init container failure suppresses
    container-level crash and probe rules.

    Ensures causal correctness:
    main containers never started due to init failure.
    """

    name = "InitContainerBlocksMain"
    category = "Compound"
    priority = 70  # Higher than container crash rules

    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "OOMKilled",
        "ReadinessProbeFailure",
        "StartupProbeFailure",
        "RepeatedProbeFailureEscalation",
        "MultiContainerPartialFailure",
    ]

    phases = ["Pending", "Init", "CrashLoopBackOff"]

    requires = {
        "pod": True,
    }

    FAILURE_REASONS = {
        "Error",
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "CreateContainerConfigError",
    }

    def matches(self, pod, events, context) -> bool:
        init_statuses = pod.get("status", {}).get("initContainerStatuses", [])
        if not init_statuses:
            return False

        for cs in init_statuses:
            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})

            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_REASONS:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        failing_init = "<unknown>"

        for cs in pod.get("status", {}).get("initContainerStatuses", []):
            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})
            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_REASONS:
                failing_init = cs.get("name")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_CONTAINER_FAILURE",
                    message="Init container failed before main containers could start",
                    blocking=True,
                    role="init_root",
                ),
                Cause(
                    code="MAIN_CONTAINERS_NOT_STARTED",
                    message="Main containers blocked by failing init container",
                    blocking=True,
                    role="kubelet_intermediate",
                ),
                Cause(
                    code="POD_INITIALIZATION_FAILED",
                    message="Pod failed during initialization phase",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Init container failure prevented pod startup",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Init container entered failure state",
                "Main containers not fully initialized",
                "Pod stuck in initialization phase",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod initialization blocked by init container failure"
                ],
                f"container:{failing_init}": [
                    "Init container failed prior to main container start"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {failing_init}",
                "Validate init container image and commands",
                "Inspect external dependencies required during initialization",
            ],
            "blocking": True,
        }
