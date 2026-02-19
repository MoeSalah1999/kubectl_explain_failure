from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule



class AdmissionWebhookDeniedRule(FailureRule):
    """
    Detects failures caused by admission webhooks rejecting Pod creation.
    Triggered by:
      - event.reason == FailedCreate
      - event.message contains 'admission webhook'
    High enterprise relevance.
    """
    name = "AdmissionWebhookDenied"
    category = "Admission"
    priority = 29

    requires = {"pod": True}

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            reason = e.get("reason")
            msg = (e.get("message") or "").lower()
            if reason == "FailedCreate" and "admission webhook" in msg:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ADMISSION_WEBHOOK_DENIED",
                    message="Admission webhook rejected pod creation",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook denied pod creation",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event containing 'admission webhook'",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission webhook prevented pod creation"
                ]
            },
            "likely_causes": [
                "Webhook policy rejecting pod spec",
                "Namespace-specific security restrictions",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get validatingwebhookconfigurations",
                "kubectl get mutatingwebhookconfigurations",
            ],
        }
    