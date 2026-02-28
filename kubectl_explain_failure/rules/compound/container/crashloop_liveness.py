from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class CrashLoopLivenessProbeCompoundRule(FailureRule):
    """
    Detects Pods that enter CrashLoopBackOff due to repeated
    liveness probe failures, indicating that the container
    cannot remain healthy even when properly scheduled.

    Signals:
    - Unhealthy events observed in pod timeline
    - BackOff events observed in pod timeline
    - CrashLoopBackOff follows liveness probe failures

    Interpretation:
    The container is repeatedly failing its liveness probe, which
    causes the kubelet to restart it. This results in a CrashLoopBackOff
    condition, preventing the Pod from achieving stable running state.

    Scope:
    - Timeline + container health layer
    - Deterministic (event-based correlation)
    - Acts as a compound check for liveness probe induced CrashLoops

    Exclusions:
    - Does not include CrashLoops caused by configuration changes
    - Does not include transient startup failures unrelated to liveness probes
    """
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
                    code="LIVENESS_PROBE_CONTEXT",
                    message="Timeline shows repeated liveness probe failures",
                    role="container_health_context",
                ),
                Cause(
                    code="LIVENESS_PROBE_FAILED",
                    message="Liveness probe failed repeatedly",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASH_LOOP",
                    message="Container restarted repeatedly (BackOff events observed)",
                    role="workload_symptom",
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
