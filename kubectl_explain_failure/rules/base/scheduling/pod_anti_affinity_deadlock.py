from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PodAntiAffinityDeadlockRule(FailureRule):
    """
    Detects scheduling failures caused by Pod anti-affinity constraints
    that cannot be satisfied due to existing pods on nodes.

    Signals:
    - FailedScheduling events
    - Message mentions 'anti-affinity' or 'conflict'

    Scope:
    - Scheduling deadlocks due to pod placement rules
    - Deterministic based on event message and timeline
    """

    name = "PodAntiAffinityDeadlock"
    category = "Scheduling"
    priority = 30
    deterministic = True
    blocks = []
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    phases = ["Pending"]

    AFFINITY_MARKERS = (
        "anti-affinity",
        "podAffinity rules not satisfied",
        "pod anti-affinity conflict",
    )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            if e.get("reason") != "FailedScheduling":
                continue
            msg = (e.get("message") or "").lower()
            if any(marker in msg for marker in self.AFFINITY_MARKERS):
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ANTI_AFFINITY_CONFLICT",
                    message="Pod anti-affinity constraints conflict with existing pods",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_AFFINITY",
                    message="Scheduler unable to place pod due to anti-affinity rules",
                    role="scheduling_symptom",
                ),
                Cause(
                    code="WORKLOAD_PLACEMENT_BLOCKED",
                    message="Pod cannot be scheduled on any node matching anti-affinity constraints",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "Scheduler reports pod anti-affinity conflict",
        ]

        return {
            "rule": self.name,
            "root_cause": "Pod anti-affinity prevents scheduling",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {f"pod:{pod_name}": ["Pod anti-affinity conflict"]},
            "likely_causes": [
                "Existing pods occupy nodes in conflict with pod anti-affinity rules",
                "PodSpec requests impossible placement",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check Pod.spec.affinity.podAntiAffinity",
                "kubectl get pods -o wide",
            ],
        }
