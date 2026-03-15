from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, timeline_has_event


class ReadOnlyRootFilesystemWriteRule(FailureRule):
    """
    Detects container crashes caused by attempts to write to a read-only root filesystem.

    Signals:
    - Pod in CrashLoopBackOff
    - Event message includes 'read-only file system'

    Interpretation:
    Hardened security policies may mount the container's root filesystem
    as read-only. Any write attempt by the container will trigger a
    kernel-level OSError and result in container termination.

    Scope:
    - Container-level failure
    - Deterministic if events are observed
    """

    name = "ReadOnlyRootFilesystemWriteAttempt"
    category = "Container"
    priority = 50
    deterministic = True
    blocks = []
    requires = {
        "objects": [],
    }

    container_states = ["terminated", "waiting"]
    supported_phases = ["CrashLoopBackOff"]

    def matches(self, pod, events, context) -> bool:
        """
        Returns True if any container terminated with a read-only filesystem error.
        """
        timeline: Timeline | None = context.get("timeline")
        if timeline:
            if timeline_has_event(timeline, kind="Generic", phase="Failure"):
                for e in timeline.events:
                    msg = e.get("message", "").lower()
                    if "read-only file system" in msg:
                        return True

        # fallback: check container termination messages
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            term = state.get("terminated")
            if term:
                msg = term.get("message", "").lower()
                if "read-only file system" in msg:
                    return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CRASHLOOP_DETECTED",
                    message="Pod is in CrashLoopBackOff due to container failures",
                    role="runtime_context",
                ),
                Cause(
                    code="READ_ONLY_FS_WRITE_ATTEMPT",
                    message="Container attempted to write to a read-only filesystem",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_TERMINATED",
                    message="Container terminated due to filesystem write failure",
                    role="workload_symptom",
                ),
            ]
        )

        # Collect evidence
        evidence = []
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            term = state.get("terminated")
            if term:
                msg = term.get("message", "")
                if "read-only file system" in msg.lower():
                    evidence.append(f"{cs.get('name')}: {msg}")

        return {
            "rule": self.name,
            "root_cause": "Container attempted to write to a read-only filesystem",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": evidence
            or ["Event log indicates read-only filesystem write attempt"],
            "object_evidence": {
                f"pod:{pod_name}": ["Read-only root filesystem write detected"]
            },
            "likely_causes": [
                "Pod security policy enforced read-only root filesystem",
                "Hardening of container image or cluster security context",
                "Application misconfigured to write to root filesystem",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check container securityContext.readOnlyRootFilesystem",
                "Check PodSecurityPolicy or OPA/Gatekeeper policies",
            ],
        }
