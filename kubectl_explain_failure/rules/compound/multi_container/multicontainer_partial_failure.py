from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class MultiContainerPartialFailureRule(FailureRule):
    """
    Detects multi-container Pods where at least one container is Ready
    while another container is in a failure state, resulting in partial
    workload degradation.

    Signals:
    - Pod.status.containerStatuses contains 2 or more containers
    - At least one container has ready=True
    - At least one container reason in [CrashLoopBackOff, Error, OOMKilled]

    Interpretation:
    One container within the Pod is failing while others continue
    running successfully. The Pod remains in Running phase, but
    functionality is degraded because a subset of containers is
    not operational.

    Scope:
    - Pod + container health layer
    - Deterministic (object-state based)
    - Acts as a compound guard to prevent generic pod-level blame
    when failure is isolated to specific containers

    Exclusions:
    - Does not include single-container Pods
    - Does not include full Pod failure where all containers are failing
    - Does not include controller-level rollout or scheduling failures
    """

    name = "MultiContainerPartialFailure"
    category = "Compound"
    priority = 62  # Must outrank generic crash rules

    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "OOMKilled",
        "ContainerCreateConfigError",
    ]

    phases = ["Running", "CrashLoopBackOff"]

    container_states = ["waiting", "terminated", "running"]

    requires = {
        "pod": True,
    }

    FAILURE_STATES = {"CrashLoopBackOff", "Error", "OOMKilled"}

    def matches(self, pod, events, context) -> bool:
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if len(statuses) < 2:
            return False  # Not multi-container

        ready_count = 0
        failing_count = 0

        for cs in statuses:
            if cs.get("ready"):
                ready_count += 1

            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})

            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_STATES:
                failing_count += 1

        # At least one healthy AND one failing container
        return ready_count >= 1 and failing_count >= 1

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        failing_container = "<unknown>"
        healthy_container = "<unknown>"

        for cs in pod.get("status", {}).get("containerStatuses", []):
            if cs.get("ready") and healthy_container == "<unknown>":
                healthy_container = cs.get("name")

            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})
            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_STATES and failing_container == "<unknown>":
                failing_container = cs.get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PARTIAL_CONTAINER_FAILURE_DETECTED",
                    message="Pod has both healthy and failing containers",
                    role="container_health_context",
                ),
                Cause(
                    code="CONTAINER_PARTIAL_FAILURE",
                    message="At least one container is in CrashLoop or failure state",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PARTIALLY_UNAVAILABLE",
                    message="Pod functionality degraded due to partial container failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Partial container failure within multi-container pod",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "At least one container is Ready",
                "At least one container is failing",
                "Failure limited to subset of containers",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Pod contains both healthy and failing containers"],
                f"container:{failing_container}": [
                    "Container in CrashLoop or failure state"
                ],
                f"container:{healthy_container}": ["Container remains Ready"],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {failing_container}",
                "Inspect container dependencies and shared volumes",
                "Validate container-specific configuration and environment",
            ],
            "blocking": True,
        }
