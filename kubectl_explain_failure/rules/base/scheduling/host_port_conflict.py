from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class HostPortConflictRule(FailureRule):
    """
    Detects scheduling failure due to hostPort already allocated.
    Triggered by FailedScheduling events referencing hostPort conflicts.
    """

    name = "HostPortConflict"
    category = "Scheduling"
    priority = 100
    blocks = ["FailedScheduling"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        entries = getattr(timeline, "events", []) 

        for entry in entries:
            reason = str(entry.get("reason", "")).lower()
            message = str(entry.get("message", "")).lower()

            if reason == "failedscheduling" and (
                "hostport" in message or
                "port conflict" in message or
                "port conflicts" in message or
                "port is already allocated" in message
            ):
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
