from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PrivilegedNotAllowedRule(FailureRule):
    """
    Detects Pod admission rejection caused by a privileged container
    being disallowed by cluster security policy.

    This rule matches when admission events (typically FailedCreate or Failed)
    contain denial messages indicating that `securityContext.privileged=true`
    is not permitted.

    Detection Signals:
      - timeline event.reason in {"FailedCreate", "Failed"}
      - event.message contains:
            * "privileged containers are not allowed"
            * or a combination of "privileged" and "not allowed"

    Scope:
      - Admission phase (Pod never scheduled)
      - Security policy enforcement (PodSecurity Admission, validating
        admission policies, or legacy PodSecurityPolicy)

    Exclusions:
      - Does not attempt to distinguish between PodSecurity Admission,
        custom admission webhooks, or deprecated PodSecurityPolicy.
      - Does not inspect container specs directly — relies on event evidence.
    """
    name = "PrivilegedNotAllowed"
    category = "Admission"
    priority = 30
    deterministic = True
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for entry in timeline.raw_events:
            message = str(entry.get("message", "")).lower()
            reason = str(entry.get("reason", "")).lower()

            # Explicit privileged denial patterns
            if "privileged containers are not allowed" in message:
                return True

            if "privileged" in message and "not allowed" in message:
                return True

            # Defensive admission-style detection
            if reason in {"failedcreate", "failed"} and "privileged" in message:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SECURITY_ADMISSION_ACTIVE",
                    message="Pod Security Admission or equivalent policy engine is enforcing security constraints",
                    role="cluster_security_context",
                ),
                Cause(
                    code="PRIVILEGED_MODE_RESTRICTED",
                    message="Cluster policy forbids containers with securityContext.privileged=true",
                    role="policy_rule",
                ),
                Cause(
                    code="PRIVILEGED_CONTAINER_DENIED",
                    message="Admission controller rejected pod due to privileged container configuration",
                    blocking=True,
                    role="authorization_root",
                ),
                Cause(
                    code="POD_CREATION_BLOCKED",
                    message="Pod rejected during admission",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod rejected because privileged containers are not allowed",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Admission event detected",
                "Event message references privileged container denial",
            ],
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    "Admission rejection detected",
                    "Message contains privileged container denial",
                ]
            },
            "likely_causes": [
                "Namespace enforces restricted PodSecurity profile",
                "PodSecurity Admission blocks privileged=true",
                "Cluster-wide policy denies privileged containers",
                "Legacy PodSecurityPolicy disallows privileged containers",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Remove privileged=true from container securityContext",
                "Review namespace PodSecurity level (restricted/baseline/privileged)",
                "Inspect validating admission policies",
            ],
        }
