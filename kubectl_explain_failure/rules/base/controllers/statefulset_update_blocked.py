from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class StatefulSetUpdateBlockedRule(FailureRule):
    """
    Detects StatefulSet rollout blocking caused by updateStrategy partitioning.

    Signals:
    - StatefulSet.spec.updateStrategy.rollingUpdate.partition is set
    - StatefulSet.status.updatedReplicas is less than the allowed rollout target
    - StatefulSet.status.updateRevision is present but not fully applied

    Interpretation:
    The StatefulSet controller is performing a rolling update, but the
    partition setting intentionally limits how many replicas may update.
    As a result, not all replicas transition to the new revision,
    and rollout progress is effectively constrained or paused.

    Scope:
    - Controller reconciliation / rollout phase
    - Deterministic (spec & status field based)
    - Captures controller-level rollout partition constraints

    Exclusions:
    - Does not detect Pod-level failures (crashes, readiness probe failures)
    - Does not detect image pull errors or runtime issues
    - Does not indicate infrastructure failure; may reflect intentional rollout configuration
    """
    name = "StatefulSetUpdateBlocked"
    category = "Controller"
    priority = 40
    deterministic = True

    requires = {
        "objects": ["statefulset"],
    }

    def matches(self, pod, events, context) -> bool:
        """
        Returns True if any StatefulSet in the context has an updateStrategy partition
        that is currently blocking rollout progress.
        """
        sts_objs = context.get("objects", {}).get("statefulset", {})
        if not sts_objs:
            return False

        for sts in sts_objs.values():
            status = sts.get("status", {})
            spec = sts.get("spec", {})
            update_strategy = spec.get("updateStrategy", {})
            partition = update_strategy.get("rollingUpdate", {}).get("partition")

            update_revision = status.get("updateRevision")
            updated_replicas = status.get("updatedReplicas", 0)

            # Blocked if updateRevision exists and updated replicas are less than replicas
            replicas = spec.get("replicas", 1)
            if update_revision and updated_replicas < (replicas - (partition or 0)):
                return True

        return False

    def explain(self, pod, events, context):
        """
        Constructs a causal explanation for StatefulSet rollout being blocked
        by partitioned updates.
        """
        sts_objs = context.get("objects", {}).get("statefulset", {})
        sts_names = list(sts_objs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="STATEFULSET_UPDATE_INITIATED",
                    message="StatefulSet controller is applying a new revision",
                    role="controller_intent",
                ),
                Cause(
                    code="STATEFULSET_PARTITION_BLOCKING",
                    message=f"StatefulSet rollout limited by updateStrategy partition: {', '.join(sts_names)}",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="STATEFULSET_ROLLOUT_INCOMPLETE",
                    message="Not all StatefulSet replicas have been updated to the new revision",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "StatefulSet rollout blocked due to updateStrategy partition",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "StatefulSet.status.updateRevision != updatedReplicas",
                "UpdateStrategy has partition limiting rollout",
                f"StatefulSet objects: {', '.join(sts_names)}",
            ],
            "object_evidence": {
                f"statefulset:{name}": ["Update blocked by partition"]
                for name in sts_names
            },
            "likely_causes": [
                "Manual partition set to avoid updating all replicas at once",
                "Pod failures or readiness gates delaying rollout",
                "Controller cannot update replicas due to resource constraints",
            ],
            "suggested_checks": [
                f"kubectl describe statefulset {name}" for name in sts_names
            ],
        }
