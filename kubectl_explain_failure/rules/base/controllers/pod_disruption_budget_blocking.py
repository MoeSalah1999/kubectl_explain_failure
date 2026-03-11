from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PodDisruptionBudgetBlockingRule(FailureRule):
    """
    Detects Pod eviction failures due to PodDisruptionBudgets (PDBs).

    Signals:
    - Event reason == "Eviction"
    - Timeline shows eviction denied due to a PDB

    Interpretation:
    Kubernetes is preventing a Pod from being evicted because
    a PodDisruptionBudget would be violated. This can block
    updates or scaling operations on controllers like
    ReplicaSets or StatefulSets.

    Scope:
    - Controller-level disruption
    - Deterministic
    - Applies to Pods managed by controllers with PDBs

    Exclusions:
    - Does not include evictions blocked for other reasons
    """

    name = "PodDisruptionBudgetBlocking"
    category = "Controller"
    priority = 50
    requires = {
        "context": ["timeline"],
    }
    deterministic = True
    blocks = ["ReplicaSetUpdateBlocked", "StatefulSetUpdateBlocked"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Look for Eviction events denied due to PDB
        return timeline_has_pattern(
            timeline,
            [
                {"reason": "Eviction", "message": "disruption budget"},
            ],
        )

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_PRESENT",
                    message=f"Pod '{pod.get('metadata', {}).get('name', '<pod>')}' exists",
                    role="workload_context",
                ),
                Cause(
                    code="PDB_BLOCKING",
                    message="Eviction denied due to PodDisruptionBudget",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="PDB_SYMPTOM",
                    message="Pod cannot be evicted, controller update may be blocked",
                    role="controller_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        return {
            "root_cause": "Eviction blocked by PodDisruptionBudget",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} is under a PDB",
                "Event: Eviction denied due to disruption budget",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Eviction blocked by PDB"]},
            "likely_causes": [
                "PodDisruptionBudget preventing eviction",
                "Controller update may be blocked",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get pdb --all-namespaces",
            ],
            "blocking": True,
        }