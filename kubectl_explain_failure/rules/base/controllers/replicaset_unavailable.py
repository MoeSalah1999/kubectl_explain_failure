from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ReplicaSetUnavailableRule(FailureRule):
    """
    Detects ReplicaSet that exists but has zero available replicas.
    Indicates controller-level availability failure.
    """

    name = "ReplicaSetUnavailable"
    category = "Controller"
    priority = 44

    requires = {
        "objects": ["replicaset"],
        "context": [],
    }

    def matches(self, pod, events, context) -> bool:
        rs_objs = context.get("objects", {}).get("replicaset", {})
        if not rs_objs:
            return False

        for rs in rs_objs.values():
            status = rs.get("status", {})
            if status.get("availableReplicas", 0) == 0:
                return True

        return False

    def explain(self, pod, events, context):
        rs_objs = context.get("objects", {}).get("replicaset", {})
        failing = [
            name
            for name, rs in rs_objs.items()
            if rs.get("status", {}).get("availableReplicas", 0) == 0
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPLICASET_RECONCILIATION_ACTIVE",
                    message="ReplicaSet controller is reconciling desired replica count",
                    role="controller_context",
                ),
                Cause(
                    code="REPLICASET_ZERO_AVAILABLE",
                    message=f"ReplicaSet(s) report zero available replicas: {', '.join(failing)}",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="PODS_NOT_READY",
                    message="Pods managed by ReplicaSet are not reaching Ready state",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "ReplicaSet has zero available replicas",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": ["ReplicaSet.status.availableReplicas == 0"],
            "object_evidence": {
                f"replicaset:{name}": ["availableReplicas=0"] for name in failing
            },
            "likely_causes": [
                "Containers crashing",
                "Readiness probes failing",
                "Image pull errors",
            ],
            "suggested_checks": [f"kubectl describe rs {name}" for name in failing],
        }
