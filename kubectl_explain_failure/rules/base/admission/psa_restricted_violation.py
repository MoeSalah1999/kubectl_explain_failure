from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PSARestrictedViolationRule(FailureRule):
    """
    Detects Pod admission rejection caused by Pod Security Admission (PSA)
    restricted profile violations.

    Signals:
    - Event reason in {"FailedCreate", "Failed"}
    - Event message includes "violates PodSecurity" with "restricted"

    Interpretation:
    The Pod violates the restricted PodSecurity profile enforced by the
    namespace or cluster, and admission is denied before scheduling.

    Scope:
    - Admission policy layer (PodSecurity Admission)
    - Deterministic (event-message based)
    - More specific than generic security context violations
    """

    name = "PSARestrictedViolation"
    category = "Admission"
    priority = 60
    deterministic = True
    blocks = ["SecurityContextViolation", "PrivilegedNotAllowed"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    PSA_MARKERS = (
        "podsecurity",
        "violates podsecurity",
        "restricted",
        "psa",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            reason = str(e.get("reason", "")).lower()
            msg = str(e.get("message", "")).lower()

            if reason not in {"failedcreate", "failed"}:
                continue

            if "podsecurity" in msg and "restricted" in msg:
                return True

            # Fallback: explicit PSA violation wording
            if "violates podsecurity" in msg and "restricted" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SECURITY_ADMISSION_ACTIVE",
                    message="Pod Security Admission is enforcing the restricted profile",
                    role="policy_context",
                ),
                Cause(
                    code="PSA_RESTRICTED_VIOLATION",
                    message="Pod violates restricted PodSecurity profile requirements",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CREATION_BLOCKED",
                    message="Pod rejected during admission due to PSA restricted policy",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod rejected due to PSA restricted profile violation",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates PodSecurity restricted profile violation",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["PodSecurity restricted admission rejection"]
            },
            "likely_causes": [
                "Privileged container or host namespace usage",
                "Disallowed volume type (hostPath)",
                "Unsafe sysctls or capabilities",
                "RunAsUser or FSGroup policy violation",
            ],
            "suggested_checks": [
                f"kubectl get ns {namespace} --show-labels",
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Review PodSecurity restricted requirements",
                "Adjust pod securityContext to meet restricted profile",
            ],
        }
