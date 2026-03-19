from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PolicyEngineUnavailableRule(FailureRule):
    """
    Detects Gatekeeper/Kyverno admission failures caused by policy-engine
    infrastructure being unavailable.

    Signals:
    - Admission events reference Gatekeeper or Kyverno webhooks
    - Event message indicates timeout, endpoint outage, DNS failure, or
      connection failure rather than a policy denial

    Interpretation:
    The policy engine itself is unavailable or unstable, so the API server
    cannot complete admission checks. This is different from a legitimate
    policy violation: the enforcement system is down.

    Scope:
    - Policy engine infrastructure + admission
    - Deterministic (event-message based)
    - Suppresses generic webhook transport failures when Gatekeeper/Kyverno
      is clearly the failing subsystem
    """

    name = "PolicyEngineUnavailable"
    category = "Compound"
    priority = 74
    deterministic = True
    blocks = [
        "WebhookFailureBlocksDeployment",
        "AdmissionWebhookServiceUnavailable",
        "AdmissionWebhookDNSFailure",
        "MutatingWebhookTimeout",
        "ValidatingWebhookTimeout",
        "WebhookCertificateExpired",
        "AdmissionWebhookCABundleMismatch",
        "AdmissionWebhookDenied",
    ]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    phases = ["Pending"]

    ENGINE_MARKERS = (
        "gatekeeper",
        "validation.gatekeeper.sh",
        "mutation.gatekeeper.sh",
        "kyverno",
    )

    AVAILABILITY_MARKERS = (
        "context deadline exceeded",
        "timed out",
        "timeout",
        "timeoutseconds",
        "no endpoints available for service",
        "service unavailable",
        "connection refused",
        "connection reset",
        "dial tcp",
        "no such host",
        "temporary failure in name resolution",
        "name resolution failed",
        "certificate has expired",
        "not yet valid",
        "unknown authority",
        "failed to verify certificate",
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

            if not any(marker in msg for marker in self.ENGINE_MARKERS):
                continue

            if any(marker in msg for marker in self.AVAILABILITY_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POLICY_ENGINE_ENFORCEMENT_ACTIVE",
                    message="Gatekeeper or Kyverno admission enforcement is configured",
                    role="policy_context",
                ),
                Cause(
                    code="POLICY_ENGINE_UNAVAILABLE",
                    message="Policy engine webhook infrastructure is unavailable",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ADMISSION_EVALUATION_BLOCKED",
                    message="Admission cannot complete required policy evaluation",
                    role="admission_intermediate",
                ),
                Cause(
                    code="POD_CREATION_BLOCKED",
                    message="Pod creation is blocked because policy engine checks cannot run",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Policy engine unavailable during admission evaluation",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission failure references Gatekeeper or Kyverno webhook",
                "Webhook failure mode indicates infrastructure unavailability",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Policy engine webhook unavailable during admission"
                ]
            },
            "likely_causes": [
                "Gatekeeper or Kyverno webhook service has no healthy endpoints",
                "Policy engine DNS or network connectivity is failing",
                "Webhook TLS configuration is invalid or expired",
            ],
            "suggested_checks": [
                "kubectl get validatingwebhookconfigurations",
                "kubectl get mutatingwebhookconfigurations",
                "Check Gatekeeper or Kyverno controller/webhook pods",
                "Inspect webhook service endpoints and TLS configuration",
            ],
        }
