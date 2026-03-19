from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class WebhookCertificateExpiredRule(FailureRule):
    """
    Detects admission failures caused by expired webhook TLS certificates.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message contains x509 expiration indicators

    Interpretation:
    The API server could not establish TLS with the webhook because its
    certificate is expired or not yet valid. Admission fails before scheduling.

    Scope:
    - Admission webhook connectivity (TLS)
    - Deterministic (event-message based)
    - More specific than generic AdmissionWebhookServiceUnavailable
    """

    name = "WebhookCertificateExpired"
    category = "Admission"
    priority = 57
    deterministic = True
    blocks = ["AdmissionWebhookDenied", "AdmissionWebhookServiceUnavailable"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    CERT_MARKERS = (
        "x509: certificate has expired",
        "x509: certificate is not yet valid",
        "certificate has expired",
        "not yet valid",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            reason = str(e.get("reason", "")).lower()
            msg = str(e.get("message", "")).lower()

            if reason not in {"failedcreate", "failed", "failedadmission"}:
                continue
            if "webhook" not in msg:
                continue
            if any(m in msg for m in self.CERT_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="WEBHOOK_TLS_REQUIRED",
                    message="Admission webhook requires TLS for API server communication",
                    role="infrastructure_context",
                ),
                Cause(
                    code="WEBHOOK_CERT_EXPIRED",
                    message="Webhook TLS certificate has expired or is not yet valid",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked due to webhook TLS failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook TLS certificate expired",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates webhook certificate expired",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Webhook TLS certificate expired or not yet valid"]
            },
            "likely_causes": [
                "Webhook certificate expired",
                "Clock skew between API server and webhook",
                "Certificate rotation failed",
            ],
            "suggested_checks": [
                "kubectl get mutatingwebhookconfigurations",
                "kubectl get validatingwebhookconfigurations",
                "Check webhook service certificate expiration",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
