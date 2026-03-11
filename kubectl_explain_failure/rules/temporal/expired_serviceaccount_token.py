from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline

class ExpiredServiceAccountTokenRule(FailureRule):
    """
    Detects CrashLoopBackOffs caused by expired ServiceAccount tokens.

    Signals:
    - Pod enters CrashLoopBackOff after token expiration window
    - Timeline contains repeated 'Unauthorized' events from Kubelet/API server
    - Pod has associated ServiceAccount

    Interpretation:
    The ServiceAccount token used by the Pod has expired.
    Containers cannot authenticate to the API server, leading
    to repeated failures and eventual CrashLoopBackOff.

    Scope:
    - Identity/RBAC layer
    - Temporal pattern based on event sequence
    """

    name = "ExpiredServiceAccountToken"
    category = "RBAC"
    priority = 45
    deterministic = True
    requires = {
        "objects": ["serviceaccount"],
        "context": ["timeline"],
    }
    blocks = ["ServiceAccountMissing", "RBACForbidden", "CrashLoopBackOff"]

    def matches(self, pod, events, context) -> bool:
        timeline: Timeline = context.get("timeline")
        if not timeline:
            return False

        # Check for repeated Unauthorized errors after token expiration
        repeated_unauth = timeline.repeated(reason="Unauthorized", threshold=2)

        # Check Pod status phase
        pod_phase = pod.get("status", {}).get("phase", "")
        crashlooping = pod_phase == "CrashLoopBackOff"

        # Ensure ServiceAccount exists
        sa_objects = context.get("objects", {}).get("serviceaccount", {})
        has_sa = bool(sa_objects)

        return repeated_unauth and crashlooping and has_sa

    def explain(self, pod, events, context):
        sa_objects = context.get("objects", {}).get("serviceaccount", {})
        sa_name = next(iter(sa_objects), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICEACCOUNT_PRESENT",
                    message=f"Pod uses ServiceAccount '{sa_name}'",
                    role="identity_context",
                ),
                Cause(
                    code="TOKEN_EXPIRED",
                    message="ServiceAccount token expired",
                    blocking=True,
                    role="identity_root",
                ),
                Cause(
                    code="CRASHLOOP_BACKOFF",
                    message="Pod repeatedly failed to authenticate to API server",
                    role="identity_symptom",
                ),
            ]
        )

        return {
            "root_cause": "ServiceAccount token expired",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"ServiceAccount '{sa_name}' attached to Pod",
                "Repeated 'Unauthorized' events in timeline",
                "Pod in CrashLoopBackOff",
            ],
            "object_evidence": {f"serviceaccount:{sa_name}": ["Token expired"]},
            "likely_causes": [
                "ServiceAccount token expired",
                "Pod unable to authenticate to API server",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod.get('metadata', {}).get('name', '<pod>')}",
                f"kubectl get secret -n {pod.get('metadata', {}).get('namespace', 'default')} {sa_name}-token-*",
            ],
            "blocking": True,
        }