from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ReplicaSetCreateFailureRule(FailureRule):
    """
    Detects ReplicaSet creation failures.
    Triggered when ReplicaSet.status.conditions[ReplicaFailure] = True.
    """
    name = "ReplicaSetCreateFailure"
    category = "Controller"
    priority = 45

    requires = {
        "objects": ["replicaset"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        rs_objs = context.get("objects", {}).get("replicaset", {})
        if not rs_objs:
            return False

        # Any ReplicaSet with failure condition?
        for rs in rs_objs.values():
            conditions = rs.get("status", {}).get("conditions", [])
            if any(cond.get("type") == "ReplicaFailure" and cond.get("status") is True for cond in conditions):
                return True

        return False

    def explain(self, pod, events, context):
        rs_objs = context.get("objects", {}).get("replicaset", {})
        rs_names = list(rs_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPLICASET_CREATION_FAILED",
                    message=f"ReplicaSet(s) failed to create pods: {', '.join(rs_names)}",
                    blocking=True
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "ReplicaSet creation failed due to ReplicaFailure condition",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "ReplicaSet.status.conditions[ReplicaFailure]=True",
                f"ReplicaSet objects: {', '.join(rs_names)}"
            ],
            "object_evidence": {
                f"replicaset:{name}": ["ReplicaFailure=True detected"] for name in rs_names
            },
            "likely_causes": [
                "Insufficient nodes to schedule pods",
                "Pod template misconfiguration",
                "Image pull errors"
            ],
            "suggested_checks": [
                f"kubectl describe rs {name}" for name in rs_names
            ],
        }


class DeploymentProgressDeadlineExceededRule(FailureRule):
    """
    Detects Deployment rollout failures due to exceeding the progress deadline.
    Triggered when Deployment.status.conditions[type=Progressing]=False
    with reason=ProgressDeadlineExceeded.
    """
    name = "DeploymentProgressDeadlineExceeded"
    category = "Controller"
    priority = 50

    requires = {
        "objects": ["deployment"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        deploy_objs = context.get("objects", {}).get("deployment", {})
        if not deploy_objs:
            return False

        for deploy in deploy_objs.values():
            conditions = deploy.get("status", {}).get("conditions", [])
            for cond in conditions:
                if cond.get("type") == "Progressing" and cond.get("status") is False and cond.get("reason") == "ProgressDeadlineExceeded":
                    return True

        return False

    def explain(self, pod, events, context):
        deploy_objs = context.get("objects", {}).get("deployment", {})
        deploy_names = list(deploy_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_PROGRESS_DEADLINE_EXCEEDED",
                    message=f"Deployment(s) exceeded progress deadline: {', '.join(deploy_names)}",
                    blocking=True
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Deployment rollout failed due to ProgressDeadlineExceeded",
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Deployment.status.conditions[type=Progressing]=False",
                "Reason=ProgressDeadlineExceeded",
                f"Deployment objects: {', '.join(deploy_names)}"
            ],
            "object_evidence": {
                f"deployment:{name}": ["ProgressDeadlineExceeded detected"] for name in deploy_names
            },
            "likely_causes": [
                "Pods failed to become ready in time",
                "Node capacity insufficient for rollout",
                "Container image pull or crash failures"
            ],
            "suggested_checks": [
                f"kubectl describe deployment {name}" for name in deploy_names
            ],
        }
