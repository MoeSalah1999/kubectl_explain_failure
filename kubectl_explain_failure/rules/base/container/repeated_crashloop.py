from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class RepeatedCrashLoopRule(FailureRule):
    name = "RepeatedCrashLoop"
    category = "Container"
    priority = 14
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    phases = ["Running"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_pattern(timeline, r"BackOff")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPEATED_CRASH_LOOP",
                    message="Container repeatedly crashing over time",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container is repeatedly crashing",
            "confidence": 0.9,
            "blocking": True,
            "causes": chain,
            "evidence": ["BackOff pattern detected in event timeline"],
            "object_evidence": {f"pod:{pod_name}": ["Repeated crash pattern detected"]},
            "likely_causes": [
                "Application instability",
                "Invalid container configuration",
                "Dependency failures",
            ],
            "suggested_checks": [
                f"kubectl logs {pod_name} -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
