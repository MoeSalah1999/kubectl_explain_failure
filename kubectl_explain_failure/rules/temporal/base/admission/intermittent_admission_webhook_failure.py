from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class IntermittentAdmissionWebhookFailureRule(FailureRule):
    """
    Detects unstable admission webhook infrastructure where failures and
    successful creations alternate over time.

    Example pattern:
    WebhookTimeout -> Success -> WebhookTimeout -> Success

    Signals:
    - At least two webhook-related admission failures
    - At least one successful controller create event between failures
    - Alternating failure/success behavior in controller-facing events

    Interpretation:
    Admission infrastructure is flapping rather than being fully down.
    Some create requests succeed while others fail, which commonly points to
    overloaded webhook backends, intermittent networking, unstable webhook
    replicas, or flapping policy-engine readiness.

    Scope:
    - Temporal admission instability
    - Non-deterministic (pattern-based)
    """

    name = "IntermittentAdmissionWebhookFailure"
    category = "Temporal"
    priority = 66
    deterministic = False
    blocks = [
        "MutatingWebhookTimeout",
        "ValidatingWebhookTimeout",
        "AdmissionWebhookServiceUnavailable",
        "AdmissionWebhookDNSFailure",
    ]
    requires = {
        "context": ["timeline"],
    }
    phases = ["Pending", "Running"]

    SUCCESS_REASONS = {"SuccessfulCreate"}

    CONTROLLER_SOURCES = {
        "replicaset-controller",
        "deployment-controller",
    }

    FAILURE_MARKERS = (
        "webhook",
        "gatekeeper",
        "kyverno",
    )

    FLAP_WINDOW_MINUTES = 20

    def _source_component(self, event) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _is_webhook_failure(self, event) -> bool:
        reason = str(event.get("reason", "")).lower()
        msg = str(event.get("message", "")).lower()
        source = self._source_component(event)
        if reason not in {"failedcreate", "failed", "failedadmission"}:
            return False
        if source and source not in self.CONTROLLER_SOURCES:
            return False
        return any(marker in msg for marker in self.FAILURE_MARKERS)

    def _is_success(self, event) -> bool:
        source = self._source_component(event)
        if source and source not in self.CONTROLLER_SOURCES:
            return False
        return str(event.get("reason", "")) in self.SUCCESS_REASONS

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        ordered = timeline.events_within_window(self.FLAP_WINDOW_MINUTES)
        failure_indexes = [
            idx for idx, event in enumerate(ordered) if self._is_webhook_failure(event)
        ]
        if len(failure_indexes) < 2:
            return False

        # Require a successful create between two failures, indicating flapping.
        for first, second in zip(failure_indexes, failure_indexes[1:], strict=False):
            if any(self._is_success(event) for event in ordered[first + 1 : second]):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ADMISSION_WEBHOOK_EVALUATION_ACTIVE",
                    message="Admission webhooks are intermittently evaluating create requests",
                    role="admission_context",
                ),
                Cause(
                    code="ADMISSION_WEBHOOK_FLAPPING",
                    message="Admission webhook infrastructure alternates between failing and succeeding",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CREATE_REQUEST_OUTCOME_UNSTABLE",
                    message="Controller create attempts intermittently succeed and fail",
                    role="admission_intermediate",
                ),
                Cause(
                    code="WORKLOAD_CREATION_UNSTABLE",
                    message="Workload creation remains unstable due to admission flapping",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Intermittent admission webhook failures causing unstable workload creation",
            "confidence": 0.87,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Controller events for {pod_name} show alternating webhook failures and SuccessfulCreate events",
                f"Alternating events occurred within {self.FLAP_WINDOW_MINUTES} minutes",
                "Admission webhook failures are intermittent rather than constant",
            ],
            "likely_causes": [
                "Webhook backend replicas are intermittently unhealthy",
                "Admission webhook is overloaded under burst traffic",
                "Network path to webhook service is unstable",
            ],
            "suggested_checks": [
                "Inspect webhook service latency and error rates",
                "Check webhook controller pod restarts and readiness",
                "Review API server admission webhook error logs",
            ],
        }
