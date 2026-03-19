from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class AdmissionWebhookCABundleMismatchRule(FailureRule):
    """
    Detects admission failures caused by CA bundle mismatch for webhook TLS.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message includes x509 unknown authority / verification failures

    Interpretation:
    The API server could not verify the webhook TLS certificate because
    the CA bundle configured in the webhook does not match the certificate
    chain presented by the webhook service.

    Scope:
    - Admission webhook TLS verification
    - Deterministic (event-message based)
    - More specific than generic AdmissionWebhookServiceUnavailable
    """

    name = "AdmissionWebhookCABundleMismatch"
    category = "Admission"
    priority = 57
    deterministic = True
    blocks = ["AdmissionWebhookDenied", "AdmissionWebhookServiceUnavailable"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    CA_MARKERS = (
        "x509: certificate signed by unknown authority",
        "x509: unknown authority",
        "certificate signed by unknown authority",
        "failed to verify certificate",
        "tls: bad certificate",
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
            if any(m in msg for m in self.CA_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="WEBHOOK_CA_BUNDLE_CONFIGURED",
                    message="Admission webhook CA bundle is configured for TLS verification",
                    role="infrastructure_context",
                ),
                Cause(
                    code="WEBHOOK_CA_BUNDLE_MISMATCH",
                    message="Webhook certificate could not be verified by configured CA bundle",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked due to webhook TLS verification failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook CA bundle mismatch blocked pod admission",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates webhook CA bundle verification failure",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Webhook TLS verification failed (CA bundle mismatch)"
                ]
            },
            "likely_causes": [
                "Webhook CA bundle is outdated or incorrect",
                "Webhook certificate rotated without updating CA bundle",
                "Certificate chain is incomplete",
            ],
            "suggested_checks": [
                "kubectl get mutatingwebhookconfigurations -o yaml",
                "kubectl get validatingwebhookconfigurations -o yaml",
                "Verify webhook caBundle matches service certificate",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
