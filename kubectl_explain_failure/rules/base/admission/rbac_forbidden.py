from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RBACForbiddenRule(FailureRule):
    """
    Detects RBAC authorization failures.
    Signals:
      - event.reason == FailedCreate
      - event.message contains 'forbidden'
      - API error message contains 'cannot'
    """

    name = "RBACForbidden"
    category = "Admission"
    priority = 28

    requires = {
        "pod": True,
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            if e.get("reason") == "FailedCreate":
                msg = (e.get("message") or "").lower()
                if "forbidden" in msg or "cannot" in msg:
                    if "exceed" in msg or "limit" in msg:
                        return False
                    if "user" in msg or "cannot create" in msg:
                        return True

        # Check pod.status.message
        status_msg = (pod.get("status", {}).get("message") or "").lower()
        if "forbidden" in status_msg or "cannot" in status_msg:
            if "limit" in status_msg or "exceed" in status_msg:
                return False
            if "user" in status_msg or "cannot create" in status_msg:
                return True

        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RBAC_FORBIDDEN",
                    message="Kubernetes API denied action due to RBAC policy",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "RBAC authorization failure prevented Pod creation",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event containing 'forbidden'",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to RBAC authorization failure"
                ]
            },
            "likely_causes": [
                "ServiceAccount lacks required Role/ClusterRole binding",
                "User lacks create permission for resource",
                "Missing verb in Role (e.g., create, get, list)",
            ],
            "suggested_checks": [
                f"kubectl auth can-i create pods -n {namespace}",
                f"kubectl describe rolebinding -n {namespace}",
                "kubectl describe clusterrolebinding",
            ],
        }
