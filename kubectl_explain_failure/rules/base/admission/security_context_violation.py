from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SecurityContextViolationRule(FailureRule):
    """
    Detects Pod rejection due to PodSecurity or legacy PSP violations.
    Triggered by admission denial events referencing security context violations.
    """

    name = "SecurityContextViolation"
    category = "Admission"
    priority = 31

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        entries = getattr(timeline, "events", [])

        for entry in entries:
            message = str(entry.get("message", "")).lower()
            reason = str(entry.get("reason", "")).lower()

            if "podsecurity" in message:
                return True
            if "violates podsecurity" in message:
                return True
            if "podsecuritypolicy" in message:
                return True
            if reason == "failedcreate" and "security" in message:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        timeline = context.get("timeline")
        entries = getattr(timeline, "events", []) if timeline else []

        violation_messages = []

        for entry in entries:
            message = str(entry.get("message", "")).lower()
            reason = str(entry.get("reason", "")).lower()

            if (
                "podsecurity" in message
                or "violates podsecurity" in message
                or "podsecuritypolicy" in message
                or (reason == "failedcreate" and "security" in message)
            ):
                violation_messages.append(entry.get("message"))

        chain = CausalChain(
            causes=[
                Cause(
                    code="SECURITY_CONTEXT_VIOLATION",
                    message="Pod rejected by PodSecurity / PSP admission controller",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod rejected due to security policy violation",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Admission event indicates PodSecurity or PSP violation",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": (
                    violation_messages
                    if violation_messages
                    else ["PodSecurity / PSP admission rejection detected"]
                )
            },
            "likely_causes": [
                "Disallowed Linux capabilities",
                "Privileged container not permitted",
                "HostPath or restricted volume usage",
                "RunAsUser, FSGroup, or SELinux policy violation",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl get ns {namespace} --show-labels",
                "Review PodSecurity admission level (baseline/restricted)",
            ],
        }
