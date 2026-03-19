from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class MutatingWebhookPatchConflictRule(FailureRule):
    """
    Detects Pod admission failures caused by mutating webhook patch conflicts.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message mentions mutating webhook and patch conflict/apply failure

    Interpretation:
    The mutating webhook attempted to modify the admission object, but
    the patch could not be applied due to a conflict or invalid patch.
    Admission fails before the Pod is scheduled.

    Scope:
    - Admission phase (mutating webhook)
    - Deterministic (event-message based)
    - More specific than generic AdmissionWebhookDenied
    """

    name = "MutatingWebhookPatchConflict"
    category = "Admission"
    priority = 57
    deterministic = True
    blocks = ["AdmissionWebhookDenied"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    PATCH_MARKERS = (
        "failed to apply patch",
        "patch conflict",
        "conflicts with",
        "jsonpatch",
        "json patch",
        "invalid patch",
    )

    TYPE_MARKERS = (
        "mutating webhook",
        "mutatingwebhookconfiguration",
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
                continue
            if any(m in msg for m in self.PATCH_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="MUTATING_WEBHOOK_CONFIGURED",
                    message="Mutating admission webhook is configured for this workload",
                    role="cluster_policy_context",
                ),
                Cause(
                    code="MUTATING_PATCH_CONFLICT",
                    message="Mutating webhook patch could not be applied due to conflict",
                    role="admission_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked by mutating webhook patch failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Mutating webhook patch conflict blocked pod admission",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates mutating webhook patch conflict",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Mutating webhook patch could not be applied"]
            },
            "likely_causes": [
                "Mutating webhook patch conflicts with other admission mutations",
                "Webhook produced invalid JSON patch",
                "Webhook schema expectations no longer match the API object",
            ],
            "suggested_checks": [
                "kubectl get mutatingwebhookconfigurations",
                "Review webhook patch logic and admission logs",
                "Check for multiple mutating webhooks touching same fields",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
