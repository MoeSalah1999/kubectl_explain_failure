from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class OwnerBlockedPodRule(FailureRule):
    """
    Deployment ProgressDeadlineExceeded
    → ReplicaSet degraded
    → Pod Pending
    """

    name = "OwnerBlockedPod"
    category = "Compound"
    priority = 56 
    blocks = ["ReplicaSetUnavailable", "ReplicaSetCreateFailure"]
    requires = {
        "objects": ["deployment", "replicaset"],
    }
    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        deployments = objects.get("deployment", {})
        replicasets = objects.get("replicaset", {})

        if not deployments or not replicasets:
            return False

        # Deployment condition: ProgressDeadlineExceeded
        deployment_blocked = False
        for dep in deployments.values():
            for cond in dep.get("status", {}).get("conditions", []):
                if (
                    cond.get("type") == "Progressing"
                    and cond.get("reason") == "ProgressDeadlineExceeded"
                ):
                    deployment_blocked = True
                    break

        if not deployment_blocked:
            return False

        # ReplicaSet degraded (desired > ready)
        rs_degraded = False
        for rs in replicasets.values():
            desired = rs.get("status", {}).get("replicas", 0)
            ready = rs.get("status", {}).get("readyReplicas", 0)
            if desired > ready:
                rs_degraded = True
                break

        if not rs_degraded:
            return False

        return True

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        dep_name = next(iter(objects.get("deployment", {})), "<unknown>")
        rs_name = next(iter(objects.get("replicaset", {})), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_PROGRESS_DEADLINE_EXCEEDED",
                    message="Deployment exceeded its progress deadline",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="REPLICASET_DEGRADED",
                    message="ReplicaSet has unavailable replicas",
                    blocking=True,
                    role="controller_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending due to controller failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Deployment rollout stalled causing ReplicaSet degradation and Pod Pending",
            "confidence": 0.97,
            "causes": chain,
            "evidence": [
                f"Deployment {dep_name} reports ProgressDeadlineExceeded",
                f"ReplicaSet {rs_name} has fewer ready replicas than desired",
                "Pod phase is Pending",
            ],
            "object_evidence": {
                f"deployment:{dep_name}": ["ProgressDeadlineExceeded"],
                f"replicaset:{rs_name}": ["Unavailable replicas"],
            },
            "suggested_checks": [
                f"kubectl describe deployment {dep_name}",
                f"kubectl describe replicaset {rs_name}",
                "Check image, readiness probes, and rollout strategy",
            ],
            "blocking": True,
        }
