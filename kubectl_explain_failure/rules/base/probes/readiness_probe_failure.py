from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ReadinessProbeFailureRule(FailureRule):
    """
    Detects containers that are running but not ready due to failing readiness probes.
    Triggered when:
      - Pod phase=Running
      - container ready=False
      - events indicate readiness probe failure
    """

    name = "ReadinessProbeFailure"
    category = "Container"
    priority = 20
    blocks = ["NotReady"]
    requires = {
        "context": ["timeline"],
    }
    phases = ["Running"]

    container_states = ["running"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Must have at least one container not ready
        not_ready = any(
            not c.get("ready", True)
            for c in pod.get("status", {}).get("containerStatuses", [])
        )

        if not not_ready:
            return False

        # Detect readiness probe failure patterns in event messages
        readiness_failures = any(
            "readiness probe" in (e.get("message", "").lower())
            and "fail" in (e.get("message", "").lower())
            for e in timeline.raw_events
        )

        return readiness_failures

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="READINESS_PROBE_CONFIGURED",
                    message="Container has readinessProbe configured",
                    role="healthcheck_context",
                ),
                Cause(
                    code="READINESS_PROBE_FAILED",
                    message="Readiness probe checks are failing",
                    blocking=True,
                    role="container_health_root",
                ),
                Cause(
                    code="POD_NOT_READY",
                    message="Pod is running but not Ready",
                    role="workload_symptom",
                ),
            ]
        )
        return {
            "rule": self.name,
            "root_cause": "Container failing readinessProbe checks",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} is running but not ready",
                "Event messages indicate readinessProbe failure",
            ],
            "object_evidence": {f"pod:{pod_name}": ["readinessProbe failure detected"]},
            "likely_causes": [
                "Application not ready during startup",
                "Incorrect readinessProbe configuration",
                "Slow initialization time",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review readinessProbe configuration in Pod spec",
            ],
        }
