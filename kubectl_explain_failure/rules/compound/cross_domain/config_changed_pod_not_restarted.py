from datetime import datetime, timezone

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ConfigChangedButPodNotRestartedRule(FailureRule):
    """
    Detects workloads where a ConfigMap changed but Pods were not restarted.

    Signals:
    - ConfigMap resourceVersion or generation changed
    - Pod start time predates the config change
    - No rollout events occurred

    Interpretation:
    Kubernetes does not automatically restart Pods when a ConfigMap
    changes unless a controller rollout occurs. Applications may
    continue running with stale configuration.

    Scope:
    - Cross-domain configuration + controller behavior
    - Temporal correlation between config change and Pod lifecycle
    """

    name = "ConfigChangedButPodNotRestarted"
    category = "Compound"
    priority = 70

    requires = {
        "objects": ["configmap"],
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "CrashLoopAfterConfigChange",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        objects = context.get("objects", {})

        if not timeline:
            return False

        configmaps = objects.get("configmap", {})
        if not configmaps:
            return False

        pod_start_ts = (
            pod.get("status", {})
            .get("startTime")
        )

        if not pod_start_ts:
            return False

        try:
            pod_start = datetime.fromisoformat(pod_start_ts.replace("Z", "+00:00"))
        except Exception:
            return False

        for cm in configmaps.values():
            meta = cm.get("metadata", {})
            change_ts = meta.get("creationTimestamp")

            if not change_ts:
                continue

            try:
                config_time = datetime.fromisoformat(change_ts.replace("Z", "+00:00"))
            except Exception:
                continue

            # Config updated after pod started
            if config_time > pod_start:
                # Ensure no rollout events happened
                rollout = timeline.count(reason="Killing") + timeline.count(reason="Started")

                if rollout == 0:
                    context["stale_configmap"] = meta.get("name")
                    return True

        return False

    def explain(self, pod, events, context):
        cm_name = context.get("stale_configmap", "<configmap>")
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIGMAP_UPDATED",
                    message=f"ConfigMap '{cm_name}' changed after Pod start",
                    role="configuration_context",
                ),
                Cause(
                    code="NO_CONTROLLER_ROLLOUT",
                    message="Controller did not trigger Pod restart after configuration change",
                    role="controller_root",
                    blocking=False,
                ),
                Cause(
                    code="STALE_CONFIGURATION_RUNNING",
                    message="Application continues running with outdated configuration",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "ConfigMap updated but Pod was not restarted",
            "confidence": 0.82,
            "causes": chain,
            "evidence": [
                f"ConfigMap {cm_name} changed after Pod start",
                f"Pod {pod_name} still running original instance",
            ],
            "object_evidence": {
                f"configmap:{cm_name}": [
                    "ConfigMap updated but workload not restarted",
                ]
            },
            "likely_causes": [
                "Controller rollout not triggered",
                "Manual configuration change without restart",
                "Application expecting dynamic reload but not implemented",
            ],
            "suggested_checks": [
                f"kubectl rollout restart deployment",
                f"kubectl describe configmap {cm_name}",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": False,
        }