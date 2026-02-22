from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class CrashLoopOOMKilledRule(FailureRule):
    name = "CrashLoopOOMKilled"
    category = "Compound"
    priority = 55

    # This compound rule supersedes the simpler ones
    blocks = ["CrashLoopBackOff", "OOMKilled"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
            
        # Detect repeated BackOff via timeline (consistent with other rules)
        crashloop = timeline_has_pattern(timeline, r"BackOff")

        # Container terminated due to OOMKilled
        oom_terminated = any(
            cs.get("lastState", {}).get("terminated", {}).get("reason") == "OOMKilled"
            for cs in pod.get("status", {}).get("containerStatuses", [])
        )

        return crashloop and oom_terminated

    def explain(self, pod, events, context):

        # Extract container names that were OOMKilled
        oom_containers = [
            cs.get("name")
            for cs in pod.get("status", {}).get("containerStatuses", [])
            if cs.get("lastState", {}).get("terminated", {}).get("reason")
            == "OOMKilled"
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="OOM_KILLED",
                    message="Container terminated due to OOMKilled (memory limit exceeded)",
                    blocking=True,
                ),
                Cause(
                    code="CRASH_LOOP",
                    message="Container repeatedly restarted (BackOff events observed)",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name")

        return {
            "rule": self.name,
            "root_cause": "CrashLoopBackOff caused by container OOMKilled (memory exhaustion)",
            "confidence": 0.98,
            "causes": chain,
            "evidence": [
                "BackOff events observed in timeline",
                "Container lastState terminated with reason OOMKilled",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"OOMKilled containers: {', '.join(oom_containers)}"
                ]
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review container memory limits and requests",
                "Inspect application memory usage patterns",
                "Consider increasing memory limits",
            ],
            "blocking": True,
        }
