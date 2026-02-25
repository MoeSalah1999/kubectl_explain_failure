from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class OOMKilledRule(FailureRule):
    name = "OOMKilled"
    category = "Container"
    priority = 16
    deterministic = True
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
                    code="CONTAINER_EXECUTING",
                    message="Container was running and consuming memory",
                    role="execution_context",
                ),
                Cause(
                    code="MEMORY_LIMIT_EXCEEDED",
                    message="Container exceeded its memory limit",
                    blocking=True,
                    role="resource_root",
                ),
                Cause(
                    code="OOM_KILL_TERMINATION",
                    message="Kubelet terminated the container due to out-of-memory condition",
                    role="workload_symptom",
                ),
            ]
        )
        evidence = []
        object_evidence = {}

        for cs in pod.get("status", {}).get("containerStatuses", []):
            last_state = cs.get("lastState", {})
            terminated = last_state.get("terminated")
            if terminated and terminated.get("reason") == "OOMKilled":
                name = cs.get("name")
                evidence.append(
                    f"Container '{name}' terminated: reason=OOMKilled"
                )
                object_evidence[f"pod:{pod_name}"] = [
                    f"Container '{name}' terminated due to OOMKilled"
                ]

        return {
            "rule": self.name,
            "root_cause": "Container was terminated due to out-of-memory",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
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
