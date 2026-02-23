from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class FailedSchedulingRule(FailureRule):
    """
    Scheduler cannot place Pod
    → Pod remains Pending
    """

    name = "FailedScheduling"
    category = "Scheduling"
    priority = 16
    blocks = []
    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- Must have structured Scheduling Failure ---
        if not timeline_has_event(
            timeline,
            kind="Scheduling",
            phase="Failure",
        ):
            return False

        # --- Exclude more specific scheduling causes ---
        # We inspect all FailedScheduling events in the timeline.
        specific_patterns = [
            "insufficient",
            "affinity",
            "topology",
            "hostport",
            "taint",
        ]

        for e in events:
            if e.get("reason") != "FailedScheduling":
                continue

            msg = (e.get("message") or "").lower()
            if any(p in msg for p in specific_patterns):
                return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod["metadata"]["name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler could not place Pod on any node",
                    blocking=True,
                    role="scheduling_root",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains in Pending phase",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Scheduler could not place Pod on any node",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Events contain FailedScheduling from default-scheduler",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Scheduler emitted FailedScheduling event"]
            },
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get nodes -o wide",
                "kubectl describe node <node>",
            ],
        }