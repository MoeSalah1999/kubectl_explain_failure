from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CrashLoopAfterConfigChangeRule(FailureRule):
    """
    ConfigMap update detected
    → CrashLoopBackOff begins shortly after
    """

    name = "CrashLoopAfterConfigChange"
    category = "Compound"
    priority = 60  # Higher than simple CrashLoop rules
    blocks = [
        "CrashLoopBackOff",
        "ConfigMapNotFound",
        "InvalidEntrypoint",
    ]

    phases = ["Running", "CrashLoopBackOff"]

    requires = {
        "context": ["timeline"],
    }

    container_states = ["waiting", "terminated"]

    CONFIG_UPDATE_REASONS = {
        "ConfigMapUpdated",
        "ConfigMapChange",
        "Updated",
    }

    CRASH_REASONS = {
        "BackOff",
        "CrashLoopBackOff",
    }

    MAX_TIME_DELTA_SECONDS = 300  # 5 minutes correlation window

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect ConfigMap update event
        config_events = [
            e for e in timeline.raw_events
            if e.get("reason") in self.CONFIG_UPDATE_REASONS
        ]

        if not config_events:
            return False

        # Detect crashloop events
        crash_events = [
            e for e in timeline.raw_events
            if e.get("reason") in self.CRASH_REASONS
        ]

        if not crash_events:
            return False

        # Ensure crash happened shortly after config change
        duration = timeline.duration_between(
            lambda e: e.get("reason") in self.CONFIG_UPDATE_REASONS
            or e.get("reason") in self.CRASH_REASONS
        )

        if duration <= 0 or duration > self.MAX_TIME_DELTA_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        container_name = "<unknown>"
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            if any(k in state for k in ["waiting", "terminated"]):
                container_name = cs.get("name", "<unknown>")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIGMAP_UPDATED",
                    message="ConfigMap was modified prior to failure",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="CONTAINER_CRASH_AFTER_CONFIG",
                    message="Container began crashing after configuration change",
                    blocking=True,
                    role="container_intermediate",
                ),
                Cause(
                    code="POD_CRASHLOOP",
                    message="Pod entered CrashLoopBackOff state",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoop triggered by recent ConfigMap change",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "ConfigMap update event detected",
                "CrashLoopBackOff occurred shortly after update",
                f"Time delta <= {self.MAX_TIME_DELTA_SECONDS} seconds",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "CrashLoop observed after configuration modification"
                ],
                f"container:{container_name}": [
                    "Container crashes began after ConfigMap update"
                ],
            },
            "suggested_checks": [
                f"kubectl describe configmap",
                f"kubectl rollout history deployment",
                "Compare previous ConfigMap values",
                "Validate application configuration parsing",
            ],
            "blocking": True,
        }
