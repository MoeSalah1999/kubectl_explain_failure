from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class EtcdObjectSizeLimitExceededRule(FailureRule):
    """
    Detects Kubernetes API admission failures caused by objects exceeding
    the etcd object size limit.

    Signals:
    - Event message contains "request is too large"
    - Event message contains "Request entity too large"
    - Event message contains "object size exceeds limit"

    Interpretation:
    The Kubernetes API server rejected the object because it exceeds
    the maximum object size supported by etcd (typically ~1.5MB).

    This often occurs when:
    - A ConfigMap or Secret contains very large data
    - An annotation blob becomes excessively large
    - A generated manifest embeds large binary content

    Scope:
    - API admission layer
    - Deterministic (event message based)

    Exclusions:
    - Storage provisioning failures
    - etcd connectivity issues
    """

    name = "EtcdObjectSizeLimitExceeded"
    category = "Admission"
    priority = 85
    deterministic = True

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ContainerCreateConfigError",
        "FailedMount",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return (
            timeline_has_pattern(timeline, "request is too large")
            or timeline_has_pattern(timeline, "Request entity too large")
            or timeline_has_pattern(timeline, "object size exceeds limit")
        )

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="API_REQUEST_ATTEMPTED",
                    message="Kubernetes API attempted to persist object",
                    role="admission_context",
                ),
                Cause(
                    code="ETCD_OBJECT_SIZE_LIMIT",
                    message="Object exceeds maximum size allowed by etcd",
                    blocking=True,
                    role="admission_root",
                ),
                Cause(
                    code="OBJECT_REJECTED_BY_API",
                    message="API server rejected the object due to size limit",
                    role="admission_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Kubernetes object exceeds etcd size limit",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Event indicates request entity too large",
                "etcd rejected object due to size limit",
            ],
            "likely_causes": [
                "ConfigMap or Secret contains very large data",
                "Annotations exceed Kubernetes size limits",
                "Application embedded large binary content in manifest",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect ConfigMaps or Secrets referenced by the Pod",
                "Check annotation sizes in the object manifest",
            ],
            "blocking": True,
        }
