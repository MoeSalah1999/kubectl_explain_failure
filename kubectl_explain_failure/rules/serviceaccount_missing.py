from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import has_event
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ServiceAccountMissingRule(FailureRule):
    name = "ServiceAccountMissing"
    category = "Compound"
    priority = 56

    # Supersedes simpler Pod creation failure signals
    blocks = ["FailedCreatePod"]

    requires = {
        "objects": ["serviceaccount"],  # check if serviceaccount object exists
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        sa_failed_event = has_event(events, "FailedCreate") and "serviceaccount" in str(events).lower()
        sa_backoff = timeline_has_pattern(timeline, r"FailedCreate") if timeline else False
        return sa_failed_event or sa_backoff

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_ACCOUNT_MISSING",
                    message="Referenced ServiceAccount not found",
                    blocking=True,
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
                "RBAC prevents pod from using ServiceAccount"
            ],
            "suggested_checks": [
                f"kubectl get serviceaccount -n {pod.get('metadata', {}).get('namespace', 'default')}",
                f"kubectl describe pod {pod_name}",
                "Verify namespace and RBAC permissions for ServiceAccount"
            ]
        }
