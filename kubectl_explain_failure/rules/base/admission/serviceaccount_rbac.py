from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ServiceAccountRBACCompoundRule(FailureRule):
    """
    Detects RBAC authorization failures affecting a Pod that references
    an existing ServiceAccount.

    Signals:
      - A ServiceAccount object exists in the namespace
      - No "ServiceAccount not found" condition is present
      - Event messages contain RBAC authorization errors
        (e.g., "forbidden", "cannot", referencing serviceaccount)

    Interpretation:
      The ServiceAccount exists, but RBAC policies deny required
      permissions for the Pod's identity, resulting in admission
      or API authorization failures.

    Scope:
      - Admission / authorization phase
      - Deterministic (event-message based)
      - Supersedes simpler RBACForbidden and ServiceAccountMissing rules
    """

    name = "ServiceAccountRBACCompound"
    category = "Admission"
    priority = 55
    blocks = ["RBACForbidden", "ServiceAccountMissing"]
    requires = {
        "objects": ["serviceaccount"],
        "context": ["timeline"],
    }
    deterministic = True

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        serviceaccounts = objects.get("serviceaccount", {})

        if not serviceaccounts:
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # If we have FailedCreate events referencing missing SA,
        # let ServiceAccountMissingRule handle it.
        missing_pattern = any(
            "failedcreate" in msg and "serviceaccount" in msg
            for msg in (e.get("message", "").lower() for e in timeline.raw_events)
        )

        if missing_pattern:
            return False

        # Detect RBAC forbidden patterns in events
        forbidden_detected = any(
            "forbidden" in msg and "serviceaccount" in msg and "cannot" in msg
            for msg in (e.get("message", "").lower() for e in timeline.raw_events)
        )

        return forbidden_detected

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        sa_name = next(iter(objects.get("serviceaccount", {})), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICEACCOUNT_ATTACHED",
                    message="Pod is configured to use a ServiceAccount",
                    role="identity_context",
                ),
                Cause(
                    code="RBAC_POLICY_EVALUATED",
                    message="Kubernetes API evaluated RBAC permissions for the ServiceAccount",
                    role="authorization_context",
                ),
                Cause(
                    code="RBAC_DENIED",
                    message="RBAC policy denies required permissions",
                    blocking=True,
                    role="authorization_root",
                ),
                Cause(
                    code="API_ACCESS_BLOCKED",
                    message="Pod cannot access required Kubernetes resources",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "ServiceAccount RBAC restrictions prevent Pod from accessing required resources",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                f"ServiceAccount {sa_name} is configured",
                "Events contain 'forbidden' authorization errors",
            ],
            "object_evidence": {
                f"serviceaccount:{sa_name}": ["RBAC denial observed"],
            },
            "suggested_checks": [
                f"kubectl describe sa {sa_name}",
                f"kubectl auth can-i --as=system:serviceaccount:<ns>:{sa_name} <verb> <resource>",
                "Inspect RoleBinding / ClusterRoleBinding",
            ],
            "blocking": True,
        }
