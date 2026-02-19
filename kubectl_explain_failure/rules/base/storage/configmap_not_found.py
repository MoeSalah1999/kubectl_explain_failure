from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ConfigMapNotFoundRule(FailureRule):
    """
    Container configuration fails because a referenced ConfigMap
    does not exist.
    → Kubelet cannot construct container spec
    → Container cannot start
    """

    name = "ConfigMapNotFound"
    category = "ConfigMap"
    priority = 50

    # Only relevant during container creation
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
        # Presence-based contract: graph may contain empty configmap set
        "objects": ["configmap"],
    }

    deterministic = True
    blocks = []

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Canonical Kubernetes signal
        if not timeline_has_pattern(
            timeline,
            [{"reason": "CreateContainerConfigError"}],
        ):
            return False

        # Ensure message references ConfigMap
        for e in events:
            if (
                e.get("reason") == "CreateContainerConfigError"
                and "configmap" in e.get("message", "").lower()
            ):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        # Attempt to extract missing ConfigMap name from event message
        missing_name = "<unknown>"
        for e in events:
            if e.get("reason") == "CreateContainerConfigError":
                msg = e.get("message", "")
                # Typical message format:
                # "configmap \"my-config\" not found"
                parts = msg.split('"')
                if len(parts) >= 2:
                    missing_name = parts[1]
                break

        root_cause_msg = "Referenced ConfigMap does not exist"

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIGMAP_REFERENCE",
                    message="Pod references a ConfigMap",
                    role="workload_context",
                ),
                Cause(
                    code="CONFIGMAP_NOT_FOUND",
                    message=f"ConfigMap '{missing_name}' not found",
                    blocking=True,
                    role="config_root",
                ),
                Cause(
                    code="CONTAINER_CONFIG_ERROR",
                    message="Container configuration cannot be constructed",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Event: CreateContainerConfigError",
                f"ConfigMap '{missing_name}' not found",
            ],
            "object_evidence": {
                f"configmap:{missing_name}": [
                    "ConfigMap not found in namespace"
                ]
            },
            "likely_causes": [
                "ConfigMap name typo",
                "ConfigMap deleted",
                "ConfigMap never created",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get configmap",
                f"kubectl get configmap {missing_name}",
            ],
        }
