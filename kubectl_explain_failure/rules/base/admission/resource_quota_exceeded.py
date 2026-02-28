from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ResourceQuotaExceededRule(FailureRule):
    """
    Detects Pod admission failures caused by namespace ResourceQuota exhaustion.

    Signals:
      - Pod.status.reason == "FailedCreate"
      - Event.reason == "ExceededQuota"
      - Event.message contains "exceeded quota"

    Interpretation:
      The namespace has an active ResourceQuota object, and the
      requested Pod would exceed one or more enforced limits
      (e.g., CPU, memory, storage, object count). The API server
      rejects Pod creation during admission.

    Scope:
      - Admission phase only (Pod remains Pending)
      - Deterministic (status / event based detection)
      - Represents a policy-enforced resource constraint
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
                    code="RESOURCE_QUOTA_ACTIVE",
                    message=f"Namespace '{namespace}' enforces ResourceQuota policies",
                    role="policy_context",
                ),
                Cause(
                    code="RESOURCE_REQUEST_EVALUATED",
                    message="Pod resource requests evaluated against namespace quota",
                    role="policy_context",
                ),
                Cause(
                    code="RESOURCE_QUOTA_EXCEEDED",
                    message=f"Namespace '{namespace}' exceeded its ResourceQuota",
                    role="policy_root",
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
