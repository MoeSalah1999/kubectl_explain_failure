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
    phases = ["Running"]

    container_states = ["running"]

    def matches(self, pod, events, context) -> bool:
        # Pod must have status.containerStatuses
        for c in pod.get("status", {}).get("containerStatuses", []):
            if not c.get("ready", True):
                # Check for readiness probe failure events
                for e in events or []:
                    msg = (e.get("message") or "").lower()
                    if "readiness probe" in msg and "fail" in msg:
                        return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="READINESS_PROBE_FAILED",
                    message="Container readinessProbe failing",
                    blocking=True,
                )
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
