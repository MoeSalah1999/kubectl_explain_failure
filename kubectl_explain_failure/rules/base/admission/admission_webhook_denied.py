from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class AdmissionWebhookDeniedRule(FailureRule):
    """
    Detects Pod creation failures caused by admission webhooks rejecting the Pod.

    Signals:
      - timeline event.reason == "FailedCreate"
      - event.message contains "admission webhook"

    Interpretation:
      The Pod was blocked by an external admission webhook, which
      enforces custom or enterprise policies (validating or mutating).

    Scope:
      - Admission phase (Pod rejected before scheduling)
      - Deterministic (event-message based)
      - Relevant for enterprise environments with webhooks enabled

    Exclusions:
      - Does not capture standard PodSecurity or LimitRange violations
      - Does not indicate kubelet-level failures or node scheduling issues
    """

    name = "AdmissionWebhookDenied"
    category = "Admission"
    priority = 29

    requires = {"pod": True}

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
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
                    code="ADMISSION_WEBHOOK_PRESENT",
                    message="Admission webhook is configured in the cluster/namespace",
                    role="cluster_policy_context",
                ),
                Cause(
                    code="WEBHOOK_POLICY_EVALUATED",
                    message="Webhook evaluated Pod spec against policy constraints",
                    role="policy_rule",
                ),
                Cause(
                    code="ADMISSION_WEBHOOK_DENIED",
                    message="Webhook rejected pod creation",
                    blocking=True,
                    role="authorization_root",
                ),
                Cause(
                    code="POD_CREATION_BLOCKED",
                    message="Pod creation blocked during admission",
                    role="workload_symptom",
                ),
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
                f"pod:{pod_name}": ["Admission webhook prevented pod creation"]
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
