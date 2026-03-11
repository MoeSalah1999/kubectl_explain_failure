from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class HPAUnableToScaleRule(FailureRule):
    """
    Detects HorizontalPodAutoscaler (HPA) failing to scale Pods.

    Signals:
    - HPA exists for this deployment/statefulset
    - Metrics unavailable or API server metric errors
    - Pods remain pending despite HPA desired replicas

    Interpretation:
    HPA cannot scale the target because metrics are unavailable or
    Pod scheduling is blocked, leaving workload under-provisioned.
    """

    name = "HPAUnableToScale"
    category = "Compound"
    priority = 55
    deterministic = True
    blocks = ["FailedScheduling", "AffinityUnsatisfiable"]
    requires = {
        "objects": ["hpa", "pod"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        objects = context.get("objects", {})
        hpa_objs = objects.get("hpa", {})

        if not hpa_objs or not timeline:
            return False

        # Check if any Pod is stuck pending
        pods = objects.get("pod", {})
        pending_pods = [
            p for p in pods.values()
            if p.get("status", {}).get("phase") == "Pending"
        ]
        if not pending_pods:
            return False

        # Check if timeline shows metrics unavailable or HPA unable to scale
        metrics_blocked = timeline_has_event(timeline, kind="Generic", phase="Failure", source="metrics-server")
        return metrics_blocked

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        hpa_name = next(iter(objects.get("hpa", {"<unknown>": {}})), "<unknown>")
        pods = objects.get("pod", {})
        pending_pods = [p.get("metadata", {}).get("name", "<pod>") for p in pods.values() if p.get("status", {}).get("phase") == "Pending"]

        root_cause_msg = f"HPA '{hpa_name}' unable to scale due to metrics unavailability or pods pending"
        chain = CausalChain(
            causes=[
                Cause(
                    code="HPA_PRESENT",
                    message=f"HPA '{hpa_name}' exists for the workload",
                    role="workload_context",
                ),
                Cause(
                    code="METRICS_UNAVAILABLE",
                    message="Metrics unavailable or API errors prevent scaling",
                    blocking=True,
                    role="controller_root",
                ),
                Cause(
                    code="PODS_PENDING",
                    message=f"Pods stuck pending: {', '.join(pending_pods)}",
                    role="controller_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"HPA object present: {hpa_name}",
                f"Pending Pods: {', '.join(pending_pods)}",
                "Timeline indicates metrics unavailability",
            ],
            "object_evidence": {f"hpa:{hpa_name}": [root_cause_msg]},
            "likely_causes": [
                "Metrics-server not reporting",
                "API server metrics error",
                "Pod scheduling blocked by resource constraints",
            ],
            "suggested_checks": [
                f"kubectl describe hpa {hpa_name}",
                "kubectl get --raw /apis/metrics.k8s.io/v1beta1/",
                f"kubectl get pods --field-selector=status.phase=Pending",
            ],
            "blocking": True,
        }