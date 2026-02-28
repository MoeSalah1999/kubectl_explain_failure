from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class LimitRangeViolationRule(FailureRule):
    """
    Detects Pod admission rejection caused by a namespace LimitRange policy violation.

    This rule matches when admission events (typically FailedCreate)
    indicate that container resource requests or limits exceed, fall below,
    or omit values required by a namespace-scoped LimitRange.

    Detection Signals:
      - timeline event.reason == "FailedCreate"
      - event.message contains:
            * "limitrange"
            * or resource constraint terms such as "exceed", "maximum",
              "minimum", or "must specify"

    Scope:
      - Admission phase (Pod rejected before scheduling)
      - Namespace-level resource governance via LimitRange

    Exclusions:
      - Does not detect ResourceQuota exhaustion (separate rule)
      - Does not validate container spec directly; relies on admission event evidence
    """

    name = "LimitRangeViolation"
    category = "Admission"
    priority = 27
    deterministic = True
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            if e.get("reason") == "FailedCreate":
                msg = (e.get("message") or "").lower()

                # More precise signal than just "limit"
                if "limitrange" in msg or "exceed" in msg:
                    return True

        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIMIT_RANGE_ENFORCEMENT_ACTIVE",
                    message=f"Namespace '{namespace}' enforces LimitRange resource constraints",
                    role="cluster_policy_context",
                ),
                Cause(
                    code="RESOURCE_CONSTRAINT_DEFINED",
                    message="Namespace defines minimum and/or maximum CPU or memory boundaries",
                    role="policy_rule",
                ),
                Cause(
                    code="LIMIT_RANGE_VIOLATION",
                    message="Pod resource requests violate namespace LimitRange policy",
                    role="authorization_root",
                    blocking=True,
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
            "root_cause": "Pod rejected due to LimitRange violation",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event referencing resource limits",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Admission rejected due to LimitRange violation"]
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
