from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class PreStopHookFailureRule(FailureRule):
    """
    Detects Pods failing to terminate gracefully due to PreStop hook failures.

    Signals:
    - Container lifecycle PreStop hook failed
    - Pod termination was blocked or delayed

    Interpretation:
    The container's PreStop hook did not complete successfully, preventing
    normal shutdown. This can cause cascading shutdown delays for dependent
    containers or workloads.

    Scope:
    - Container-level failure
    - Deterministic (based on container event timeline)
    """

    name = "PreStopHookFailure"
    category = "Container"
    priority = 70
    deterministic = True
    blocks = []
    requires = {
        "objects": ["pod"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Look for PreStop hook failures in structured timeline
        return timeline_has_event(
            timeline,
            kind="Generic",
            phase="Failure",
            source="PreStopHook",
        )

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown-pod")
        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_TERMINATION_INITIATED",
                    message="Pod termination started",
                    role="infrastructure_context",
                ),
                Cause(
                    code="PRESTOP_HOOK_FAILED",
                    message="Container PreStop hook execution failed",
                    role="container_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_SHUTDOWN_BLOCKED",
                    message="Container could not terminate cleanly",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod termination blocked by PreStop hook failure",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod: {pod_name}",
                "Detected PreStop hook failure in container events",
            ],
            "object_evidence": {f"pod:{pod_name}": ["PreStop hook failed"]},
            "likely_causes": [
                "PreStop hook command exited with non-zero status",
                "Hook command timed out",
                "Dependent container processes blocked shutdown",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl logs <pod> -c <container> --previous",
            ],
        }
