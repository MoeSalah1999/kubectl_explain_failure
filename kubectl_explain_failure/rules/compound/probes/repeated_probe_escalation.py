from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RepeatedProbeFailureEscalationRule(FailureRule):
    """
    Detects Pods whose containers experience sustained probe failures,
    resulting in kubelet-driven restart escalation and workload instability.

    Signals:
    - Repeated probe failure events (Unhealthy, ProbeError, Failed)
    within a sustained time window
    - Failure count exceeds restart escalation threshold
    - Container state transitions include waiting or terminated

    Interpretation:
    The container repeatedly fails its configured liveness or readiness
    probes over a sustained duration. The kubelet interprets these failures
    as health degradation and triggers restart escalation, causing the Pod
    to become unstable or enter CrashLoopBackOff.

    Scope:
    - Container health + kubelet execution layer
    - Deterministic (event timeline + container state correlation)
    - Acts as a compound escalation rule suppressing simple probe failure
    and generic CrashLoopBackOff rules when sustained probe failure is
    the upstream cause

    Exclusions:
    - Does not include single or transient probe failures
    - Does not include application crashes unrelated to probes
    - Does not include scheduling or infrastructure-level failures
    """

    name = "RepeatedProbeFailureEscalation"
    category = "Compound"
    priority = 58  # Higher than simple probe rules
    blocks = [
        "ReadinessProbeFailure",
        "StartupProbeFailure",
        "CrashLoopBackOff",
    ]
    phases = ["Running", "CrashLoopBackOff"]

    requires = {
        "context": ["timeline"],
    }

    container_states = ["waiting", "terminated"]

    FAILURE_REASONS = {
        "Unhealthy",
        "ProbeError",
        "Failed",
    }

    MIN_FAILURE_COUNT = 5
    MIN_DURATION_SECONDS = 300  # 5 minutes sustained

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Convert seconds → minutes for events_within_window
        minutes_window = self.MIN_DURATION_SECONDS / 60

        window_events = []
        for reason in self.FAILURE_REASONS:
            window_events.extend(
                timeline.events_within_window(
                    minutes=minutes_window,
                    reason=reason,
                )
            )

        # Only match if sustained failures exceed threshold
        if len(window_events) < self.MIN_FAILURE_COUNT:
            return False

        return True
    
    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        # Attempt to extract first affected container name
        container_name = "<unknown>"
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            last_state = cs.get("lastState", {})
            if any(k in state for k in ["waiting", "terminated"]) or any(
                k in last_state for k in ["waiting", "terminated"]
            ):
                container_name = cs.get("name", "<unknown>")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_SUSTAINED_PROBE_FAILURE",
                    message="Container failed health probes repeatedly over sustained duration",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_RESTART_ESCALATION",
                    message="Kubelet restarted container due to repeated probe failures",
                    role="execution_intermediate",
                ),
                Cause(
                    code="POD_UNSTABLE",
                    message="Pod remains unstable due to restart escalation from probe failures",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Repeated probe failures caused container restart escalation",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Multiple probe failure events detected",
                f"Failures sustained >= {self.MIN_DURATION_SECONDS} seconds",
                "Container restart behavior observed",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Probe failure pattern exceeded restart threshold"],
                f"container:{container_name}": [
                    "Repeated probe failures triggered restart escalation"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect probe configuration (path, port, timeoutSeconds)",
                "Check application health endpoint behavior",
                "Validate resource limits and startup time",
            ],
            "blocking": True,
        }
