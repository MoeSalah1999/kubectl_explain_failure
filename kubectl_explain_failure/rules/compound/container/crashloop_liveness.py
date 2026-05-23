from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


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
    blocks = ["CrashLoopBackOff", "LivenessProbeFailure"]

    requires = {
        "context": ["timeline"],
    }

    def _event_targets_current_pod(self, event, pod) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind", "") or "").lower()
        if kind and kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _is_current_pod_backoff(self, event, pod) -> bool:
        if not self._event_targets_current_pod(event, pod):
            return False
        return str(event.get("reason", "") or "").lower() == "backoff"

    def _is_current_pod_unhealthy_probe_failure(self, event, pod) -> bool:
        if not self._event_targets_current_pod(event, pod):
            return False
        reason = str(event.get("reason", "") or "").lower()
        message = str(event.get("message", "") or "").lower()
        if reason not in {"unhealthy", "failed", "killing"}:
            return False
        return "probe" in message and (
            "fail" in message or "restart" in message or "restarted" in message
        )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        recent_events = timeline.events_within_window(20)
        if not recent_events:
            recent_events = timeline.raw_events

        crashloop = any(
            self._is_current_pod_backoff(event, pod) for event in recent_events
        )
        unhealthy = any(
            self._is_current_pod_unhealthy_probe_failure(event, pod)
            for event in recent_events
        )

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
