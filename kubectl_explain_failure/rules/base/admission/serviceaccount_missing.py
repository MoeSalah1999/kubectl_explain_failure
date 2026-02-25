from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ServiceAccountMissingRule(FailureRule):
    name = "ServiceAccountMissing"
    category = "Admission"
    priority = 56
    deterministic = True

    # Supersedes simpler Pod creation failure signals
    blocks = ["FailedCreatePod"]

    requires = {
        "objects": ["serviceaccount"],  # check if serviceaccount object exists
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            reason = (e.get("reason") or "").lower()
            message = (e.get("message") or "").lower()

            if (
                reason == "failedcreate"
                and "serviceaccount" in message
                and "not found" in message
            ):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICEACCOUNT_NOT_FOUND",
                    message="Referenced ServiceAccount does not exist",
                    role="identity_context",
                ),
                Cause(
                    code="POD_CREATION_BLOCKED",
                    message="Pod rejected during admission",
                    blocking=True,
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod cannot start due to missing ServiceAccount",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedCreate events observed referencing missing ServiceAccount"
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Pod references missing ServiceAccount"]
            },
            "likely_causes": [
                "ServiceAccount deleted or misconfigured",
                "Namespace mismatch for ServiceAccount",
                "RBAC prevents pod from using ServiceAccount",
            ],
            "suggested_checks": [
                f"kubectl get serviceaccount -n {pod.get('metadata', {}).get('namespace', 'default')}",
                f"kubectl describe pod {pod_name}",
                "Verify namespace and RBAC permissions for ServiceAccount",
            ],
        }
