from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ValidatingWebhookTimeoutRule(FailureRule):
    """
    Detects Pod creation failures caused by validating admission webhook timeouts.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message contains "validating webhook" and timeout indicators

    Interpretation:
    The API server attempted to call a validating webhook, but the webhook
    did not respond within the configured timeout. The Pod admission
    request is rejected and never reaches scheduling.

    Scope:
    - Admission phase (Pod rejected before scheduling)
    - Deterministic (event-message based)
    - Supersedes generic admission webhook denial
    """

    name = "ValidatingWebhookTimeout"
    category = "Admission"
    priority = 55
    deterministic = True
    blocks = ["AdmissionWebhookDenied"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    TIMEOUT_MARKERS = (
        "context deadline exceeded",
        "timed out",
        "timeout",
        "timeoutseconds",
    )

    TYPE_MARKERS = (
        "validating webhook",
        "validatingwebhookconfiguration",
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

            if not any(t in msg for t in self.TYPE_MARKERS):
                # Some API server messages omit type; avoid mislabeling
                continue

            if any(m in msg for m in self.TIMEOUT_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="VALIDATING_WEBHOOK_CONFIGURED",
                    message="Validating admission webhook is configured for this workload",
                    role="cluster_policy_context",
                ),
                Cause(
                    code="VALIDATING_WEBHOOK_TIMEOUT",
                    message="Validating webhook did not respond before admission timeout",
                    role="admission_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked due to validating webhook timeout",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Validating admission webhook timed out during pod creation",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates validating webhook timeout",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Validating webhook timed out during admission"]
            },
            "likely_causes": [
                "Webhook service is slow or overloaded",
                "Network latency between API server and webhook",
                "Webhook timeout set too low for request payload",
            ],
            "suggested_checks": [
                "kubectl get validatingwebhookconfigurations",
                "Check webhook service logs and latency",
                "Verify webhook timeoutSeconds settings",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
