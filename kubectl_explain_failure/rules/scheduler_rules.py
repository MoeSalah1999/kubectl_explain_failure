from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptedByHigherPriorityRule(FailureRule):
    """
    Detects Pod preemption due to higher priority Pod.
    Triggered when Pod.status.reason = "Preempted".
    """

    name = "PreemptedByHigherPriority"
    category = "Scheduling"
    priority = 66

    requires = {
        "pod": True,
    }

    def matches(self, pod, events, context) -> bool:
        return pod.get("status", {}).get("reason") == "Preempted"

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_PREEMPTED",
                    message=f"Pod was preempted by a higher-priority Pod",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod was preempted by a higher-priority workload",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.status.reason=Preempted",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod.status.reason=Preempted",
                    "Scheduler evicted Pod due to higher-priority workload"
                ]
            },
            "likely_causes": [
                "Cluster resource pressure",
                "Higher-priority Pod scheduled onto the same node",
                "PreemptionPolicy allows eviction"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check PriorityClass configuration",
                "Review node capacity and resource pressure"
            ],
        }


class HostPortConflictRule(FailureRule):
    """
    Detects scheduling failure due to hostPort already allocated.
    Triggered by FailedScheduling events referencing hostPort conflicts.
    """

    name = "HostPortConflict"
    category = "Scheduling"
    priority = 65

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        if not timeline or not hasattr(timeline, "entries"):
            return False

        for entry in timeline.entries:
            reason = str(entry.get("reason", "")).lower()
            message = str(entry.get("message", "")).lower()

            if reason == "failedscheduling" and "hostport" in message:
                return True

            if "port is already allocated" in message:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="HOSTPORT_CONFLICT",
                    message="Requested hostPort already allocated on target node",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Scheduling failed due to hostPort conflict",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "FailedScheduling event detected",
                "Event message references hostPort conflict or allocated port"
            ],
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    "FailedScheduling event",
                    "Message contains hostPort conflict indication"
                ]
            },
            "likely_causes": [
                "Another Pod is using the same hostPort",
                "DaemonSet binding fixed hostPort across nodes",
                "Insufficient available nodes with free port"
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Check other Pods using the same hostPort",
                "Inspect node port allocations"
            ],
        }
