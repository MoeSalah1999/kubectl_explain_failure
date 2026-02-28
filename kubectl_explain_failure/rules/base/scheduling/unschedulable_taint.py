from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event, event_frequency


class UnschedulableTaintRule(FailureRule):
    """
    Detects Pod scheduling failures caused by untolerated node taints.

    Signals:
    - Timeline contains 'FailedScheduling' events
    - Event message references taints or missing tolerations
    - Pod lacks tolerations matching node taints

    Interpretation:
    One or more nodes in the cluster have taints that the Pod does not 
    tolerate. The scheduler cannot place the Pod onto any available node, 
    resulting in repeated FailedScheduling events and a Pending state.

    Scope:
    - Scheduler phase
    - Deterministic (event-based)
    - Captures hard taint/toleration constraint violations

    Exclusions:
    - Does not include nodeSelector or node affinity mismatches
    - Does not include resource insufficiency failures
    - Does not include priority-based preemption
    """

    name = "UnschedulableTaint"
    category = "Scheduling"
    priority = 85
    blocks = ["FailedScheduling"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- Structured scheduling failure must exist ---
        if not timeline_has_event(
            timeline,
            kind="Scheduling",
            phase="Failure",
        ):
            return False

        # --- Ensure this is truly a FailedScheduling signal ---
        if event_frequency(timeline, "FailedScheduling") == 0:
            return False

        # --- Detect taint-specific message patterns ---
        for entry in timeline.raw_events:
            if entry.get("reason") != "FailedScheduling":
                continue

            message = (entry.get("message") or "").lower()

            if (
                "taint" in message
                or "didn't tolerate" in message
                or "had taint" in message
                or "node(s) had taint" in message
            ):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_TOLERATIONS_DEFINED",
                    message=f"Pod declares tolerations",
                    role="workload_context",
                ),
                Cause(
                    code="NODE_TAINT_NOT_TOLERATED",
                    message="Available nodes have taints not tolerated by the Pod",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_TAINT",
                    message="Scheduler cannot place Pod due to untolerated node taints",
                    role="scheduler_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Scheduling failed due to untolerated node taints",
            "confidence": 0.94,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedScheduling event detected",
                "Event message references node taints or missing tolerations",
            ],
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    "FailedScheduling event",
                    "Message contains taint intolerance indication",
                ]
            },
            "likely_causes": [
                "Pod missing required tolerations",
                "Node taints restrict scheduling",
                "Cluster-wide taints prevent placement",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl describe nodes",
                "Verify pod tolerations match node taints",
            ],
        }
