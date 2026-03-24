from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PodAntiAffinityDeadlockRule(FailureRule):
    """
    Detects Pending Pods that declare hard podAntiAffinity and cannot be
    scheduled because all candidate nodes already host conflicting Pods.

    Real-world interpretation:
    - The Pod uses requiredDuringScheduling podAntiAffinity
    - The scheduler emits explicit anti-affinity FailedScheduling messages
    - Retries continue, but no successful scheduling occurs
    - This is more specific than the generic affinity-unsatisfiable fallback
    """

    name = "PodAntiAffinityDeadlock"
    category = "Scheduling"
    priority = 29
    deterministic = True
    blocks = ["AffinityUnsatisfiable", "FailedScheduling", "PendingUnschedulable"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    phases = ["Pending"]

    ANTI_AFFINITY_MARKERS = (
        "didn't match pod anti-affinity rules",
        "didn't satisfy existing pods anti-affinity rules",
        "pod anti-affinity rules",
        "inter-pod anti-affinity",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _has_required_pod_anti_affinity(self, pod: dict) -> bool:
        affinity = pod.get("spec", {}).get("affinity", {}) or {}
        pod_anti_affinity = affinity.get("podAntiAffinity", {}) or {}
        required = pod_anti_affinity.get(
            "requiredDuringSchedulingIgnoredDuringExecution", []
        )
        return bool(required)

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        if not self._has_required_pod_anti_affinity(pod):
            return False

        recent = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent:
            return False

        anti_affinity_hits = 0
        total_failures = 0
        repeated_signal = False

        for event in recent:
            message = str(event.get("message", "")).lower()
            occurrences = self._occurrences(event)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True
            if any(marker in message for marker in self.ANTI_AFFINITY_MARKERS):
                anti_affinity_hits += occurrences

        if anti_affinity_hits < 2:
            return False
        if total_failures < 2:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < 30 and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

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
                    code="POD_ANTI_AFFINITY_REQUIRED",
                    message="Pod declares required pod anti-affinity constraints",
                    role="workload_context",
                ),
                Cause(
                    code="POD_ANTI_AFFINITY_DEADLOCK",
                    message="Existing Pods occupy all candidate nodes allowed by required anti-affinity",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler rejects all nodes because anti-affinity rules remain unsatisfied",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because required pod anti-affinity is unsatisfied",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Required pod anti-affinity creates a scheduling deadlock",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Pod defines required podAntiAffinity rules",
                "FailedScheduling events explicitly reference pod anti-affinity conflicts",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Required pod anti-affinity prevents the scheduler from selecting any node"
                ]
            },
            "likely_causes": [
                "Existing replicas already occupy every eligible topology domain or node",
                "Required pod anti-affinity is stricter than the available node count",
                "Pod labels and anti-affinity selectors create an impossible placement",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check pod.spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution",
                "kubectl get pods -A -o wide --show-labels",
                "Verify enough nodes or topology domains exist to satisfy required anti-affinity",
            ],
        }
