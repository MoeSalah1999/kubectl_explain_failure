from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class DeploymentReplicaMismatchRule(FailureRule):
    """
    Detects Deployments where available replicas are less than desired replicas,
    but the Deployment has not yet reported a Progressing/Unavailable condition.

    Signals:
    - Deployment status: availableReplicas < desiredReplicas
    - No DeploymentProgressing/ReplicaSetUnavailable event yet
    - Early-stage failure (prevents rollout)

    Interpretation:
    The Deployment is failing to scale up to the desired replica count.
    No explicit error condition is present yet, so this is an early warning.
    """

    name = "DeploymentReplicaMismatch"
    category = "Controller"
    priority = 45
    deterministic = True
    requires = {
        "objects": ["deployment"],
        "context": ["timeline"],
    }
    blocks = ["DeploymentProgressDeadlineExceeded"]

    def matches(self, pod, events, context) -> bool:
        # Expect deployment object(s) in the object graph
        deployments = context.get("objects", {}).get("deployment", {})
        if not deployments:
            return False

        for dep_name, dep in deployments.items():
            status = dep.get("status", {})
            desired = status.get("replicas", 0)
            available = status.get("availableReplicas", 0)

            if desired > 0 and available < desired:
                timeline = context.get("timeline")
                # Check for no Progressing/Unavailable signals yet
                no_progressing = not timeline_has_event(
                    timeline,
                    kind="Generic",
                    phase="Failure",
                    source="DeploymentController",
                )
                if no_progressing:
                    return True
        return False

    def explain(self, pod, events, context):
        deployments = context.get("objects", {}).get("deployment", {})
        dep_name, dep = next(iter(deployments.items()))
        status = dep.get("status", {})
        desired = status.get("replicas", 0)
        available = status.get("availableReplicas", 0)

        root_msg = f"Deployment '{dep_name}' has {available}/{desired} available replicas"
        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_ROLLOUT_IN_PROGRESS",
                    message="Deployment rollout has started",
                    role="controller_context",
                ),
                Cause(
                    code="REPLICA_COUNT_MISMATCH",
                    message="Available replicas are fewer than desired replicas",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="ROLLOUT_INCOMPLETE",
                    message="Deployment has not yet made full progress; some Pods are missing or not ready",
                    role="workload_symptom",
                ),
            ]
        )


        return {
            "root_cause": root_msg,
            "confidence": 0.9,
            "causes": chain,
            "evidence": [root_msg],
            "object_evidence": {f"deployment:{dep_name}": [root_msg]},
            "likely_causes": [
                "ReplicaSet not yet created",
                "Pods scheduling slowly",
                "Cluster resource constraints",
            ],
            "suggested_checks": [
                f"kubectl get deployment {dep_name} -o yaml",
                f"kubectl describe deployment {dep_name}",
                "kubectl get rs -n <namespace> | grep <deployment_name>",
            ],
            "blocking": True,
        }