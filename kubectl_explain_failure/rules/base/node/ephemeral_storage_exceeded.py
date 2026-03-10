from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class EphemeralStorageExceededRule(FailureRule):
    """
    Detects Pods evicted due to ephemeral storage exhaustion.

    Signals:
    - Pod eviction reason: "Evicted"
    - Message includes "ephemeral-storage"

    Interpretation:
    The Pod exceeded its ephemeral storage limit and was evicted by
    the kubelet. This is distinct from node disk pressure.

    Scope:
    - Runtime / container-level
    - Deterministic (based on Pod status & events)
    """

    name = "EphemeralStorageExceeded"
    category = "Node"
    priority = 60
    deterministic = True
    blocks = []
    requires = {
        "objects": ["pod"],
    }

    def matches(self, pod, events, context) -> bool:
        """
        Match Pod eviction events for ephemeral storage.
        """
        # Pod.status.reason is "Evicted" and message contains ephemeral-storage
        status = pod.get("status", {})
        reason = status.get("reason")
        message = status.get("message", "") or ""
        if reason == "Evicted" and "ephemeral-storage" in message.lower():
            return True

        # Timeline-based fallback (recent events)
        timeline = context.get("timeline")
        if timeline:
            return timeline_has_event(
                timeline,
                kind="Generic",
                phase="Failure",
                source=None,
            ) and any(
                "ephemeral-storage" in (e.get("message") or "").lower()
                for e in events
                if e.get("reason") == "Evicted"
            )

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SCHEDULED",
                    message="Pod was scheduled and running",
                    role="runtime_context",
                ),
                Cause(
                    code="EPHEMERAL_STORAGE_EXCEEDED",
                    message="Pod consumed more ephemeral storage than allocated",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_EVICTED",
                    message="Pod eviction due to ephemeral-storage exceeded",
                    role="runtime_symptom",
                ),
            ]
        )

        message_lines = []
        status = pod.get("status", {})
        if status.get("message"):
            message_lines.append(status["message"])

        return {
            "rule": self.name,
            "root_cause": "Pod evicted due to ephemeral storage exhaustion",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod.status.reason={status.get('reason')}",
                f"Pod.status.message={status.get('message')}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Evicted due to ephemeral-storage"]
            },
            "likely_causes": [
                "Pod disk usage exceeded ephemeral-storage limits",
                "Container image layers or logs filled /tmp or emptyDir",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"Check ephemeral-storage requests/limits in Pod spec",
                "Inspect container logs and ephemeral directories (/tmp, emptyDir)",
            ],
        }