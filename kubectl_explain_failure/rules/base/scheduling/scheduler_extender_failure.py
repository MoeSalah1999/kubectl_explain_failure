from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SchedulerExtenderFailureRule(FailureRule):
    """
    Detects FailedScheduling caused by a scheduler extender error.

    Real-world interpretation:
    - The default scheduler delegates part of scheduling to an extender
    - The extender returns an error, times out, or cannot be reached
    - Scheduling fails before a node can be selected
    - This is different from a legitimate extender policy decision
    """

    name = "SchedulerExtenderFailure"
    category = "Scheduling"
    priority = 25
    deterministic = True
    blocks = ["FailedScheduling"]
    requires = {"pod": True, "context": ["timeline"]}
    phases = ["Pending"]

    FAILURE_MARKERS = (
        "extender",
        "failed to run extender",
        "scheduler extender",
        "error selecting node using extender",
    )

    ERROR_MARKERS = (
        "failed",
        "error",
        "timed out",
        "timeout",
        "context deadline exceeded",
        "i/o timeout",
        "connection refused",
        "no route to host",
        "unavailable",
    )

    def _source_component(self, event) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for event in timeline.events_within_window(15, reason="FailedScheduling"):
            message = str(event.get("message", "")).lower()
            source = self._source_component(event)

            if "scheduler" not in source and source:
                continue
            if not any(marker in message for marker in self.FAILURE_MARKERS):
                continue
            if not any(marker in message for marker in self.ERROR_MARKERS):
                continue
            return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        dominant_msg = None
        if timeline:
            messages = [
                str(event.get("message", ""))
                for event in timeline.events_within_window(
                    15, reason="FailedScheduling"
                )
                if event.get("message")
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_EXTENDER_FAILURE",
                    message="A scheduler extender returned an error during scheduling",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="The scheduler could not complete node selection because the extender failed",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because scheduling could not complete",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Scheduler extender failure prevented pod scheduling",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedScheduling event references a scheduler extender error",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod scheduling was blocked by a scheduler extender failure"
                ]
            },
            "likely_causes": [
                "Scheduler extender service is unavailable or timing out",
                "Scheduler extender returned an internal error",
                "Network connectivity to the extender is broken",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check kube-scheduler logs for extender errors",
                "Verify scheduler extender service health and connectivity",
                "Review extender timeout and filter configuration",
            ],
        }
