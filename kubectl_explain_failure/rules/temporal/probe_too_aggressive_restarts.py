from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ProbeTooAggressiveCausingRestartsRule(FailureRule):
    """
    Detects Pods repeatedly restarted due to overly aggressive
    liveness probe configuration.

    Signals:
    - Multiple "Unhealthy" probe failures
    - Container restarts escalate over time
    - Liveness probe has very small initialDelaySeconds

    Interpretation:
    The container is being restarted by Kubernetes because
    the liveness probe fails too quickly after startup.
    This usually happens when the application needs more
    warm-up time than the probe allows.

    Scope:
    - Temporal probe behavior
    - Non-deterministic (heuristic based on event patterns)
    """

    name = "ProbeTooAggressiveCausingRestarts"
    category = "Temporal"
    priority = 55

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "CrashLoopBackOff",
        "RapidRestartEscalation",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect probe failures
        probe_failures = timeline.count(reason="Unhealthy")

        if probe_failures < 3:
            return False

        # Detect restarts increasing
        restarts = sum(
            c.get("restartCount", 0)
            for c in pod.get("status", {}).get("containerStatuses", [])
        )

        if restarts < 3:
            return False

        # Check liveness probe configuration
        containers = pod.get("spec", {}).get("containers", [])
        for c in containers:
            probe = c.get("livenessProbe")
            if not probe:
                continue

            initial_delay = probe.get("initialDelaySeconds", 0)

            # Aggressive probe: <10 seconds initial delay
            if initial_delay < 10:
                context["aggressive_probe"] = True
                context["probe_initial_delay"] = initial_delay
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        delay = context.get("probe_initial_delay", 0)

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIVENESS_PROBE_CONFIGURED",
                    message="Container uses a liveness probe for health checking",
                    role="configuration_context",
                ),
                Cause(
                    code="PROBE_TOO_AGGRESSIVE",
                    message=f"Liveness probe initialDelaySeconds={delay} is too short",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_RESTART_LOOP",
                    message="Container repeatedly restarted due to failing liveness probe",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Liveness probe configuration causes repeated container restarts",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Event: Unhealthy (liveness probe failure)",
                f"Pod {pod_name} restart count increasing",
                f"Liveness probe initialDelaySeconds={delay}",
            ],
            "likely_causes": [
                "Application startup time longer than probe delay",
                "Health endpoint not ready immediately",
                "Probe configured too aggressively",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Increase livenessProbe.initialDelaySeconds",
                "Check container logs for slow startup",
            ],
            "blocking": False,
        }