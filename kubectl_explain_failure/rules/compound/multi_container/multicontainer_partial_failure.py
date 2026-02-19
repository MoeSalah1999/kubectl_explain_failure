from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class MultiContainerPartialFailureRule(FailureRule):
    """
    One container Ready
    One container CrashLoopBackOff / failing

    Prevents generic pod-level blame when only
    a subset of containers are failing.
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

            reason = (
                waiting.get("reason")
                or terminated.get("reason")
            )

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
                    code="PARTIAL_CONTAINER_FAILURE",
                    message="One container is failing while others remain healthy",
                    blocking=True,
                    role="container_root",
                ),
                Cause(
                    code="SERVICE_DEGRADATION",
                    message="Pod functionality degraded due to partial container failure",
                    blocking=True,
                    role="workload_intermediate",
                ),
                Cause(
                    code="POD_PARTIALLY_UNAVAILABLE",
                    message="Pod is not fully operational due to failing container",
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
                f"pod:{pod_name}": [
                    "Pod contains both healthy and failing containers"
                ],
                f"container:{failing_container}": [
                    "Container in CrashLoop or failure state"
                ],
                f"container:{healthy_container}": [
                    "Container remains Ready"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {failing_container}",
                "Inspect container dependencies and shared volumes",
                "Validate container-specific configuration and environment",
            ],
            "blocking": True,
        }
