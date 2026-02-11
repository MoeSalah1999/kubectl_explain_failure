from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class InitContainerFailureRule(FailureRule):
    name = "InitContainerFailure"
    category = "Compound"
    priority = 61

    # Supersedes simple init container failure signals
    blocks = ["InitContainerNonZeroExit"]

    requires = {
        "context": ["timeline"],  # timeline helps detect repeated failures
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        # Detect BackOff / repeated init container failures if timeline present
        backoff_pattern = timeline_has_pattern(timeline, r"BackOff") if timeline else False

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
                    code="INIT_CONTAINER_FAILED",
                    message="Init container exited with non-zero code",
                    blocking=True,
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod blocked due to failing init container",
            "confidence": 0.99,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Init containers failed: {', '.join(failed_containers)}"
            ],
            "object_evidence": {
                f"pod:{pod_name}": [f"Init containers failed: {', '.join(failed_containers)}"]
            },
            "likely_causes": [
                "Misconfigured init container command or image",
                "Missing dependencies required by init container",
                "Resource constraints preventing init container start"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect init container logs",
                "Check resource limits for init container",
                "Verify dependencies required by init container"
            ]
        }
