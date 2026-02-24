from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RepeatedProbeFailureEscalationRule(FailureRule):
    """
    Liveness/Readiness probe failing repeatedly
    over sustained time window
    → Container restart escalation
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
                    code="PROBE_REPEATED_FAILURE",
                    message="Container probe repeatedly failed over sustained duration",
                    blocking=True,
                    role="container_root",
                ),
                Cause(
                    code="CONTAINER_RESTART_ESCALATION",
                    message="Kubelet restarted container due to probe failures",
                    blocking=True,
                    role="kubelet_intermediate",
                ),
                Cause(
                    code="POD_UNSTABLE",
                    message="Pod remains unstable due to repeated probe failures",
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
