from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InitContainerBlocksMainRule(FailureRule):
    """
    Detects Pods whose main containers never start because an init
    container has failed, blocking the initialization sequence.

    Signals:
    - Pod.status.initContainerStatuses contains a failed state
    - Init container reason in [Error, CrashLoopBackOff,
    ImagePullBackOff, CreateContainerConfigError]
    - Main containers not yet started

    Interpretation:
    An init container failed during the initialization phase,
    preventing the kubelet from starting the main application
    containers. Because init containers must complete successfully
    before normal containers start, the Pod cannot progress to
    Running state.

    Scope:
    - Pod + container initialization layer
    - Deterministic (object-state based)
    - Acts as a compound guard to suppress container-level
    crash and probe rules when init failure is the true cause

    Exclusions:
    - Does not include failures occurring after main containers start
    - Does not include controller-level rollout failures
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
                    code="INIT_CONTAINER_FAILURE_DETECTED",
                    message=f"Init container {failing_init} entered failure state",
                    role="container_health_context",
                ),
                Cause(
                    code="INIT_CONTAINER_FAILURE",
                    message="Init container failed during Pod initialization",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_INITIALIZATION_BLOCKED",
                    message="Main containers not started due to init container failure",
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
