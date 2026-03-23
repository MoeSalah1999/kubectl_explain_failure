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

    # Strong platform identity (must indicate Gatekeeper/OPA)
    PLATFORM_MARKERS = (
        "gatekeeper",
        "validation.gatekeeper.sh",
        "opa",
    )

    # MUST indicate an actual rejection / violation
    VIOLATION_MARKERS = (
        "denied the request",
        "denied by",
        "violations:",
        "violation",
    )

    # MUST NOT be present (these indicate infra failure, not policy failure)
    AVAILABILITY_MARKERS = (
        "no endpoints available",
        "service unavailable",
        "context deadline exceeded",
        "timed out",
        "timeout",
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

            # 1. Must be Gatekeeper/OPA-related
            if not any(marker in msg for marker in self.PLATFORM_MARKERS):
                continue

            # 2. MUST NOT be infrastructure failure
            if any(marker in msg for marker in self.AVAILABILITY_MARKERS):
                continue

            # 3. Must contain explicit rejection semantics, not just mention
            # Gatekeeper or a constraint object name.
            if any(marker in msg for marker in self.VIOLATION_MARKERS):
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
