from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class AdmissionWebhookServiceUnavailableRule(FailureRule):
    """
    Detects Pod creation failures caused by admission webhook service outages.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message indicates webhook service unavailable

    Interpretation:
    The API server attempted to call an admission webhook, but the webhook
    service was unreachable (no endpoints, DNS failure, connection refused).
    The Pod admission request is rejected and never reaches scheduling.

    Scope:
    - Admission phase (Pod rejected before scheduling)
    - Deterministic (event-message based)
    - Supersedes generic admission webhook denial
    """

    name = "AdmissionWebhookServiceUnavailable"
    category = "Admission"
    priority = 56
    deterministic = True
    blocks = ["AdmissionWebhookDenied"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    UNAVAILABLE_MARKERS = (
        "no endpoints available for service",
        "service unavailable",
        "connection refused",
        "connection reset",
        "dial tcp",
        "no such host",
        "i/o timeout",
        "tls handshake timeout",
        'service "',
        "failed calling webhook",
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

            if any(m in msg for m in self.UNAVAILABLE_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ADMISSION_WEBHOOK_CONFIGURED",
                    message="Admission webhook configured for this workload",
                    role="cluster_policy_context",
                ),
                Cause(
                    code="WEBHOOK_SERVICE_UNAVAILABLE",
                    message="Admission webhook service was unreachable",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked due to webhook service outage",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook service unavailable during pod creation",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates webhook service unavailable",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Admission webhook service unavailable"]
            },
            "likely_causes": [
                "Webhook Service has no endpoints",
                "DNS resolution failure for webhook service",
                "Network connectivity issue to webhook service",
                "Webhook Deployment not running",
            ],
            "suggested_checks": [
                "kubectl get mutatingwebhookconfigurations",
                "kubectl get validatingwebhookconfigurations",
                "kubectl get endpoints -A | grep webhook",
                "Check webhook Service and Deployment health",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
