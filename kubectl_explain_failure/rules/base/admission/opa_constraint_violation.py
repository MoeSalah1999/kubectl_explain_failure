from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class OPAConstraintViolationRule(FailureRule):
    """
    Detects Pod admission rejection caused by OPA/Gatekeeper constraint violations.

    Signals:
    - Event reason in {"FailedCreate", "Failed", "FailedAdmission"}
    - Event message references Gatekeeper/OPA constraint evaluation

    Interpretation:
    A Gatekeeper (OPA) validating webhook rejected the Pod because it
    violated one or more policy constraints.

    Scope:
    - Admission policy layer (ValidatingWebhook / Gatekeeper)
    - Deterministic (event-message based)
    - More specific than generic AdmissionWebhookDenied
    """

    name = "OPAConstraintViolation"
    category = "Admission"
    priority = 58
    deterministic = True
    blocks = ["AdmissionWebhookDenied"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    OPA_MARKERS = (
        "gatekeeper",
        "opa",
        "constraint",
        "constrainttemplate",
        "admission webhook \"validation.gatekeeper.sh\"",
        "denied the request",
        "violations:",
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

            # Gatekeeper/OPA signals with constraint context
            has_platform_marker = any(m in msg for m in self.OPA_MARKERS)
            if has_platform_marker and ("constraint" in msg or "gatekeeper" in msg):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="OPA_GATEKEEPER_ACTIVE",
                    message="OPA Gatekeeper admission webhook is enforcing constraints",
                    role="policy_context",
                ),
                Cause(
                    code="OPA_CONSTRAINT_VIOLATION",
                    message="Pod violates one or more Gatekeeper constraints",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_ADMISSION_BLOCKED",
                    message="Pod creation blocked by policy engine",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "OPA Gatekeeper constraint violation blocked pod admission",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates Gatekeeper/OPA constraint violation",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Admission rejected by Gatekeeper constraint"]
            },
            "likely_causes": [
                "Pod spec violates Gatekeeper constraint policy",
                "Namespace constraint violations (labels, security, or resource rules)",
                "ConstraintTemplate updated with stricter policy",
            ],
            "suggested_checks": [
                "kubectl get constraints -A",
                "kubectl get constrainttemplates",
                "kubectl get validatingwebhookconfigurations | grep gatekeeper",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
