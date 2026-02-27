from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class StartupProbeFailureRule(FailureRule):
    """
    Detects container startup probe failures in Pods.

    Signals:
    - Timeline contains startup probe failure events
    - Container state is waiting or terminated during initialization
    - Pod phase is Pending or Running

    Interpretation:
    The container defines a startupProbe, but the probe is failing.
    Kubernetes blocks normal container lifecycle progression until
    the startup probe succeeds. Repeated failures may lead to
    container restarts and CrashLoopBackOff.

    Scope:
    - Container health check layer
    - Deterministic (event & state-based)
    - Captures initialization-phase gating failures

    Exclusions:
    - Does not include readinessProbe failures
    - Does not include livenessProbe failures after successful startup
    - Does not include image pull or configuration errors
    """

    name = "StartupProbeFailure"
    category = "Container"
    priority = 17
    blocks = ["CrashLoopBackOff", "RepeatedCrashLoop"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Running", "Pending"]

    container_states = ["terminated", "waiting"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect startup probe failure message
        startup_failure = any(
            "startup probe" in (e.get("message", "").lower())
            and "fail" in (e.get("message", "").lower())
            for e in timeline.raw_events
        )

        return startup_failure

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="STARTUP_PROBE_CONFIGURED",
                    message="Container has startupProbe configured",
                    role="healthcheck_context",
                ),
                Cause(
                    code="STARTUP_PROBE_FAILED",
                    message="Startup probe checks are failing",
                    blocking=True,
                    role="container_health_root",
                ),
                Cause(
                    code="CONTAINER_STARTUP_BLOCKED",
                    message="Container cannot complete initialization phase",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container failed startupProbe checks",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Event message indicates startupProbe failure",
                f"Pod: {pod_name}",
            ],
            "object_evidence": {f"pod:{pod_name}": ["startupProbe failure detected"]},
            "likely_causes": [
                "Application not ready during startup",
                "Incorrect probe configuration",
                "Slow initialization time",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Review startupProbe configuration in Pod spec",
            ],
        }
