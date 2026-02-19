from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class OOMKilledRule(FailureRule):
    name = "OOMKilled"
    category = "Container"
    priority = 16

    requires = {
        "pod": True,
    }

    phases = ["Running", "Failed"]
    container_states = ["terminated"]

    def matches(self, pod, events, context) -> bool:
        for cs in pod.get("status", {}).get("containerStatuses", []):
            last_state = cs.get("lastState", {})
            terminated = last_state.get("terminated")
            if terminated and terminated.get("reason") == "OOMKilled":
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="OOM_KILLED",
                    message="Container terminated due to out-of-memory",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container was terminated due to out-of-memory",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": ["Container lastState.terminated.reason = OOMKilled"],
            "object_evidence": {
                f"pod:{pod_name}": ["Container terminated with OOMKilled"]
            },
            "likely_causes": [
                "Memory limit too low",
                "Memory spike during workload",
                "Memory leak in application",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl logs {pod_name} -n {namespace}",
                "Review container memory limits and usage",
            ],
        }
