from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ReplicaSetCreateFailureRule(FailureRule):
    """
    Detects ReplicaSet reconciliation failures via the ReplicaFailure condition.

    Signals:
    - ReplicaSet.status.conditions[type="ReplicaFailure"].status == True

    Interpretation:
    The ReplicaSet controller is attempting to reconcile the desired replica count,
    but reports a ReplicaFailure condition. This indicates that the controller
    cannot successfully create or maintain the required Pods. As a result,
    the workload does not reach the desired state.

    Scope:
    - Controller reconciliation phase
    - Deterministic (status-condition based)
    - Captures controller-level replica management failures

    Exclusions:
    - Does not inspect specific underlying causes (e.g., scheduling failure,
    quota exhaustion, admission rejection, or image pull errors)
    - Does not include Pod-level runtime failures such as CrashLoopBackOff
    """

    name = "ReplicaSetCreateFailure"
    category = "Controller"
    priority = 45
    deterministic = True
    requires = {
        "objects": ["replicaset"],
    }

    def matches(self, pod, events, context) -> bool:
        rs_objs = context.get("objects", {}).get("replicaset", {})
        if not rs_objs:
            return False

        # Any ReplicaSet with failure condition?
        for rs in rs_objs.values():
            conditions = rs.get("status", {}).get("conditions", [])
            if any(
                cond.get("type") == "ReplicaFailure" and cond.get("status") is True
                for cond in conditions
            ):
                return True

        return False

    def explain(self, pod, events, context):
        rs_objs = context.get("objects", {}).get("replicaset", {})
        rs_names = list(rs_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPLICASET_DESIRED_STATE_ENFORCEMENT",
                    message="ReplicaSet controller is enforcing desired replica count",
                    role="controller_intent",
                ),
                Cause(
                    code="REPLICASET_REPLICA_FAILURE",
                    message="ReplicaSet reports ReplicaFailure=True condition",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CREATION_FAILED",
                    message="ReplicaSet failed to successfully create or maintain desired Pods",
                    role="workload_symptom",
                ),
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
                f"ReplicaSet objects: {', '.join(rs_names)}",
            ],
            "object_evidence": {
                f"replicaset:{name}": ["ReplicaFailure=True detected"]
                for name in rs_names
            },
            "likely_causes": [
                "Insufficient nodes to schedule pods",
                "Pod template misconfiguration",
                "Image pull errors",
            ],
            "suggested_checks": [f"kubectl describe rs {name}" for name in rs_names],
        }
