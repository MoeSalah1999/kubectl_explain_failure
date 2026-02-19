from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class LimitRangeViolationRule(FailureRule):
    """
    Detects Pod admission failure due to LimitRange violations.
    Signals:
      - event.reason == FailedCreate
      - event.message contains 'limit' or 'exceeds'
    """

    name = "LimitRangeViolation"
    category = "Admission"
    priority = 27

    requires = {
        "pod": True,
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            if e.get("reason") == "FailedCreate":
                msg = (e.get("message") or "").lower()
                if "limit" in msg or "exceed" in msg:
                    return True
        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIMIT_RANGE_VIOLATION",
                    message=f"Pod resource requests violate LimitRange in namespace '{namespace}'",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod rejected due to LimitRange violation",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event referencing resource limits",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to LimitRange violation"
                ]
            },
            "likely_causes": [
                "CPU request above maximum allowed",
                "Memory request above maximum allowed",
                "Missing required resource requests",
                "Container limits below minimum threshold",
            ],
            "suggested_checks": [
                f"kubectl describe limitrange -n {namespace}",
                f"kubectl get pod {pod_name} -o yaml -n {namespace}",
            ],
        }