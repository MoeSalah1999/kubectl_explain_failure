from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PodOverheadExceededNodeCapacityRule(FailureRule):
    """
    Detects scheduling failures caused by Pod overhead exceeding node capacity.

    Signals:
    - Pod.spec.overhead defined
    - Scheduler emits FailedScheduling events referencing resource exhaustion

    Interpretation:
    Kubernetes adds Pod runtime overhead to container resource requests.
    When effective resource requirements exceed available node capacity,
    the scheduler rejects placement.

    Scope:
    - Scheduler-level failure
    - Deterministic when overhead + scheduling failure signals present
    """

    name = "PodOverheadExceededNodeCapacity"
    category = "Scheduling"
    priority = 9
    deterministic = True

    blocks = ["InsufficientResources"]

    requires = {
        "pod": True,
    }

    def matches(self, pod, events, context) -> bool:
        spec = pod.get("spec", {})

        overhead = spec.get("overhead")
        if not overhead:
            return False

        failed_sched = [e for e in events if e.get("reason") == "FailedScheduling"]

        if not failed_sched:
            return False

        for e in failed_sched:
            msg = (e.get("message") or "").lower()

            if "overhead" in msg:
                return True

            if "insufficient" in msg and "overhead" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        spec = pod.get("spec", {})
        overhead = spec.get("overhead", {})

        timeline = context.get("timeline")

        failed_sched = timeline.events_within_window(
            15,
            reason="FailedScheduling",
        )

        evidence_msgs = []

        for e in failed_sched:
            msg = e.get("message")
            if not msg:
                continue

            if "overhead" in msg.lower() or "insufficient" in msg.lower():
                evidence_msgs.append(msg)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_RUNTIME_OVERHEAD_DEFINED",
                    message="Pod runtime overhead added to container resource requests",
                    role="scheduling_context",
                ),
                Cause(
                    code="EFFECTIVE_RESOURCE_EXCEEDS_NODE_CAPACITY",
                    message="Effective resource requirements exceed available node capacity",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_INSUFFICIENT_CAPACITY",
                    message="Scheduler cannot place Pod due to effective resource requirements",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        return {
            "rule": self.name,
            "root_cause": "Pod runtime overhead causes effective resource requirements to exceed node capacity",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.spec.overhead defined",
                f"Overhead resources: {overhead}",
                f"{len(failed_sched)} FailedScheduling events observed",
                *evidence_msgs[:2],
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod.spec.overhead defined",
                    f"Overhead={overhead}",
                ]
            },
            "likely_causes": [
                "RuntimeClass defines additional resource overhead",
                "Pod sandbox runtime overhead configured",
                "Cluster nodes have insufficient capacity for overhead-adjusted Pod",
            ],
            "suggested_checks": [
                f"kubectl get pod {pod_name} -o yaml",
                "kubectl describe pod",
                "kubectl describe node",
                "Check RuntimeClass overhead configuration",
            ],
        }
