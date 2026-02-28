from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class InitContainerFailureRule(FailureRule):
    """
    Detects Pods blocked due to failing init containers.

    Signals:
    - Init container state.terminated.exitCode != 0
    - Timeline may include repeated init container failures (BackOff events)

    Interpretation:
    The Pod defines one or more init containers. One or more of these containers
    exited with a non-zero status, preventing the Pod from starting its main containers.

    Scope:
    - Compound / multi-step startup failure
    - Deterministic (event & state-based)
    - Supersedes simpler InitContainerNonZeroExit signals
    """
    name = "InitContainerFailure"
    category = "Compound"
    priority = 61
    deterministic = True
    # Supersedes simple init container failure signals
    blocks = ["InitContainerNonZeroExit"]

    requires = {
        "context": ["timeline"],  # timeline helps detect repeated failures
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        # Detect BackOff / repeated init container failures if timeline present
        backoff_pattern = timeline_has_event(
            timeline,
            phase="Failure",
        )

        for cs in pod.get("status", {}).get("initContainerStatuses", []):
            term = cs.get("state", {}).get("terminated")
            if term and term.get("exitCode", 0) != 0:
                return True or backoff_pattern

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        failed_containers = [
            cs.get("name", "<unknown>")
            for cs in pod.get("status", {}).get("initContainerStatuses", [])
            if cs.get("state", {}).get("terminated", {}).get("exitCode", 0) != 0
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_CONTAINER_PRESENT",
                    message="Pod defines one or more init containers",
                    role="workload_context",
                ),
                Cause(
                    code="INIT_CONTAINER_EXIT_NONZERO",
                    message="Init container exited with non-zero status",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STARTUP_BLOCKED",
                    message="Pod cannot proceed to main containers until init succeeds",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod blocked due to failing init container",
            "confidence": 0.99,
            "causes": chain,
            "blocking": True,
            "evidence": [f"Init containers failed: {', '.join(failed_containers)}"],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"Init containers failed: {', '.join(failed_containers)}"
                ]
            },
            "likely_causes": [
                "Misconfigured init container command or image",
                "Missing dependencies required by init container",
                "Resource constraints preventing init container start",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect init container logs",
                "Check resource limits for init container",
                "Verify dependencies required by init container",
            ],
        }
