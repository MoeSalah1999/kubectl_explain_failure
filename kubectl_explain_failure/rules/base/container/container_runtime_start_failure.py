from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class ContainerRuntimeStartFailureRule(FailureRule):
    """
    Detects container startup failures due to runtime issues (containerd/cri-o).

    Signals:
    - kubelet event: "Error: failed to create containerd task"
    - Typically occurs when the container runtime cannot launch the container.

    Differentiation:
    - Different from CreateConfigError (does not indicate misconfigured entrypoint or spec errors).

    Scope:
    - Container-level failure
    - Deterministic
    """

    name = "ContainerRuntimeStartFailure"
    category = "Container"
    priority = 80
    deterministic = True
    blocks = []
    requires = {
        "context": [],
        "objects": [],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return timeline_has_event(
            timeline, kind="Generic", phase="Failure", source="kubelet"
        ) and any(
            "failed to create containerd task" in (e.get("message") or "")
            for e in (timeline.events if timeline else [])
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        evidence_events = (
            [
                e
                for e in timeline.events
                if "failed to create containerd task" in (e.get("message") or "")
            ]
            if timeline
            else []
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_RUNTIME_SIGNAL",
                    message="Kubelet detected container runtime start failure",
                    role="container_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_FAILED_TO_START",
                    message="Container could not be created by container runtime",
                    role="container_symptom",
                ),
                Cause(
                    code="POD_STARTUP_FAILED",
                    message="Pod could not start due to container runtime failure",
                    role="workload_effect",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        return {
            "rule": self.name,
            "root_cause": "Container runtime failed to start container",
            "confidence": 0.98,
            "causes": chain,
            "blocking": True,
            "evidence": [e.get("message") for e in evidence_events],
            "object_evidence": {
                f"pod:{pod_name}": [e.get("message") for e in evidence_events]
            },
            "likely_causes": [
                "Container runtime (containerd/cri-o) misconfiguration",
                "Insufficient node resources for runtime",
                "Container runtime daemon failure",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check kubelet logs for container runtime errors",
                "Verify containerd/cri-o service status on node",
            ],
        }
