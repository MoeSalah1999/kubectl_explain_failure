from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PrivilegedNotAllowedRule(FailureRule):
    """
    Detects admission rejection when privileged container is not allowed.
    Triggered by security policy denial referencing privileged=true.
    """

    name = "PrivilegedNotAllowed"
    category = "Admission"
    priority = 30

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        entries = getattr(timeline, "events", [])

        for entry in entries:
            message = str(entry.get("message", "")).lower()
            reason = str(entry.get("reason", "")).lower()

            # Explicit privileged denial patterns
            if "privileged containers are not allowed" in message:
                return True

            if "privileged" in message and "not allowed" in message:
                return True

            # Defensive: many admission denials use FailedCreate or similar
            if reason in {"failedcreate", "failed"} and "privileged" in message:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PRIVILEGED_CONTAINER_DENIED",
                    message="Privileged container not permitted by admission policy",
                    blocking=True,
                )
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
