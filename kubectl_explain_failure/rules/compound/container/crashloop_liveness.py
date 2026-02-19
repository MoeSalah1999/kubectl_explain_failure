from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern

# ---------------------------------------------------------
# Compound: CrashLoopBackOff caused by failing liveness probe
# ---------------------------------------------------------


class CrashLoopLivenessProbeCompoundRule(FailureRule):
    name = "CrashLoopLivenessProbe"
    category = "Compound"
    priority = 59

    # Supersedes simple crash loop rule
    blocks = ["CrashLoopBackOff"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        crashloop = timeline_has_pattern(timeline, r"BackOff")
        unhealthy = timeline_has_pattern(timeline, r"Unhealthy")

        return crashloop and unhealthy

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIVENESS_PROBE_FAILED",
                    message="Liveness probe failed repeatedly",
                    blocking=True,
                ),
                Cause(
                    code="CRASH_LOOP",
                    message="Container restarted repeatedly (BackOff events observed)",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "CrashLoopBackOff caused by failing liveness probe",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Unhealthy events observed in timeline",
                "BackOff events observed in timeline",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Container repeatedly failing liveness probe"]
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review livenessProbe configuration",
                "Inspect container logs",
                "Check startup time vs probe initialDelaySeconds",
            ],
        }
