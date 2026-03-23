from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class AdmissionWebhookDNSFailureRule(FailureRule):
    """
    Detects admission failures caused by DNS resolution errors when
    contacting admission webhooks.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message includes DNS failure indicators (no such host)

    Interpretation:
    The API server failed to resolve the webhook service DNS name,
    so the webhook could not be reached and admission was rejected.

    Scope:
    - Admission webhook connectivity (DNS)
    - Deterministic (event-message based)
    - More specific than generic AdmissionWebhookServiceUnavailable
    """

    name = "AdmissionWebhookDNSFailure"
    category = "Admission"
    priority = 56
    deterministic = True
    blocks = ["AdmissionWebhookDenied", "AdmissionWebhookServiceUnavailable"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    DNS_MARKERS = (
        "no such host",
        "temporary failure in name resolution",
        "name resolution failed",
        "server misbehaving",
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
            if any(m in msg for m in self.DNS_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="WEBHOOK_DNS_REQUIRED",
                    message="Admission webhook service must be resolvable via DNS",
                    role="infrastructure_context",
                ),
                Cause(
                    code="WEBHOOK_DNS_FAILURE",
                    message="DNS resolution failed for admission webhook service",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked due to webhook DNS failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook DNS resolution failure blocked pod admission",
            "confidence": 0.90,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates webhook DNS resolution failure",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Webhook DNS resolution failure"]},
            "likely_causes": [
                "CoreDNS outage or misconfiguration",
                "Webhook service name misconfigured",
                "Network policy blocking DNS",
            ],
            "suggested_checks": [
                "Check CoreDNS health",
                "Verify webhook service name in configuration",
                "kubectl get svc -A | grep webhook",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
