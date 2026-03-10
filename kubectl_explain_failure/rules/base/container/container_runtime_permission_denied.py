from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ContainerRuntimePermissionDeniedRule(FailureRule):
    """
    Detects container start failures due to runtime security restrictions.

    Signals:
    - Event.reason contains "PermissionDenied", "Seccomp", "AppArmor"
    - Syscall blocked during container start

    Interpretation:
    The container failed to start because the runtime denied
    permissions via seccomp or AppArmor. This is distinct from
    generic SecurityContextViolation (e.g., capabilities or privileged flag).

    Scope:
    - Container-level failure
    - Deterministic if event indicates explicit permission denial
    """

    name = "ContainerRuntimePermissionDenied"
    category = "Container"
    priority = 70
    deterministic = True
    blocks = []  # does not suppress other rules by default
    requires = {
        "objects": ["pod"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Structured timeline check for runtime permission denial
        return timeline.has(
            kind="Generic",
            phase="Failure",
        ) and any(
            e.get("reason") and any(term in e["reason"] for term in ["PermissionDenied", "Seccomp", "AppArmor"])
            for e in timeline.events
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        events_found = [
            e for e in timeline.events
            if e.get("reason") and any(term in e["reason"] for term in ["PermissionDenied", "Seccomp", "AppArmor"])
        ] if timeline else []

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_START_ATTEMPT",
                    message="Container attempted to start",
                    role="container_context",
                ),
                Cause(
                    code="RUNTIME_PERMISSION_DENIED",
                    message="Container runtime denied permission via seccomp or AppArmor",
                    role="container_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_FAILED_TO_START",
                    message="Container could not start due to runtime security restrictions",
                    role="container_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "unknown")
        evidence = [f"{e.get('reason')} at {e.get('eventTime')}" for e in events_found]

        return {
            "rule": self.name,
            "root_cause": "Container failed to start due to runtime permission denial",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [e.get("reason") for e in events_found]
            },
            "likely_causes": [
                "Seccomp profile blocks a required syscall",
                "AppArmor profile prevents container action",
                "Pod security context incompatible with container runtime",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check container seccomp and AppArmor profiles",
            ],
        }