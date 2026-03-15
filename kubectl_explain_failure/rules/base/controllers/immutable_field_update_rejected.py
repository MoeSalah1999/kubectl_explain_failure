from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ImmutableFieldUpdateRejectedRule(FailureRule):
    """
    Detects controller reconciliation failures caused by attempting to
    modify immutable Kubernetes object fields.

    Signals:
    - Event message indicating "field is immutable"
    - Event message indicating "immutable field"
    - Event message indicating update rejected due to immutability

    Interpretation:
    A controller attempted to update an object field that Kubernetes
    defines as immutable. The API server rejects such updates, causing
    reconciliation to fail.

    Common examples:
    - Deployment.spec.selector
    - StatefulSet.volumeClaimTemplates
    - Service.spec.clusterIP
    - PersistentVolumeClaim.spec.storageClassName

    Scope:
    - Controller reconciliation layer
    - Deterministic (event-based)

    Exclusions:
    - Admission policy failures
    - RBAC or webhook denials
    """

    name = "ImmutableFieldUpdateRejected"
    category = "Controller"
    priority = 55
    deterministic = True

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ReplicaSetCreateFailure",
        "DeploymentProgressDeadlineExceeded",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return (
            timeline_has_pattern(timeline, r"field is immutable")
            or timeline_has_pattern(timeline, r"immutable field")
            or timeline_has_pattern(timeline, r"cannot.*immutable")
        )

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTROLLER_RECONCILIATION_ATTEMPTED",
                    message="Controller attempted to reconcile the workload",
                    role="controller_context",
                ),
                Cause(
                    code="IMMUTABLE_FIELD_UPDATE_REJECTED",
                    message="Kubernetes rejected update to immutable object field",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="CONTROLLER_UPDATE_FAILED",
                    message="Controller reconciliation failed due to immutable field change",
                    role="controller_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Controller attempted to modify immutable Kubernetes field",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Event indicates immutable field update rejection",
            ],
            "likely_causes": [
                "Deployment selector modified after creation",
                "StatefulSet volumeClaimTemplates changed",
                "Service clusterIP modified",
                "PVC storageClassName changed after creation",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect controller manifest for immutable field changes",
                "Compare applied manifest with existing resource",
            ],
            "blocking": True,
        }
