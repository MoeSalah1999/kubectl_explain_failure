from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class StartupProbeFailureRule(FailureRule):
    """
    Detects containers failing startupProbe before readiness/liveness.
    Triggered by:
      - container waiting/terminated
      - event message contains 'startup probe'
    """

    name = "StartupProbeFailure"
    category = "Container"
    priority = 17
    blocks = ["CrashLoopBackOff", "RepeatedCrashLoop"]
    requires = {
        "pod": True,
    }

    phases = ["Running", "Pending"]

    container_states = ["terminated", "waiting"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            msg = (e.get("message") or "").lower()
            if "startup probe" in msg and "fail" in msg:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="STARTUP_PROBE_FAILED",
                    message="Container startupProbe failed",
                    blocking=True,
                )
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
