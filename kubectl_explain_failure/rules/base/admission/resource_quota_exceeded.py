from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ResourceQuotaExceededRule(FailureRule):
    """
    Detects Pod creation failure due to namespace ResourceQuota exhaustion.
    Signals:
      - Pod.status.reason == FailedCreate
      - OR event.reason == ExceededQuota
      - OR event.message contains 'exceeded quota'
    """

    name = "ResourceQuotaExceeded"
    category = "Admission"
    priority = 26
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

        # Pod.status reason check
        if pod.get("status", {}).get("reason") == "FailedCreate":
            return True

        # Inspect timeline events structurally
        for e in timeline.raw_events:
            reason = e.get("reason", "")
            message = (e.get("message") or "").lower()

            if reason == "ExceededQuota":
                return True

            if "exceeded quota" in message:
                return True

        return False
    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RESOURCE_QUOTA_POLICY",
                    message="Namespace ResourceQuota policies are enforced",
                    role="policy_root",
                ),
                Cause(
                    code="RESOURCE_QUOTA_EXCEEDED",
                    message=f"Namespace '{namespace}' exceeded its ResourceQuota",
                    blocking=True,
                    role="policy_root",
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
            "root_cause": "Pod creation blocked by ResourceQuota limits",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Pod.status.reason=FailedCreate or ExceededQuota event detected",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to ResourceQuota exhaustion"
                ]
            },
            "likely_causes": [
                "CPU requests exceed namespace quota",
                "Memory requests exceed namespace quota",
                "PersistentVolumeClaim storage exceeds quota",
                "Object count quota exceeded",
            ],
            "suggested_checks": [
                f"kubectl describe resourcequota -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
