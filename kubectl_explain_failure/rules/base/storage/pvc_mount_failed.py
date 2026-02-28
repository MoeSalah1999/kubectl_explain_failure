from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCMountFailedRule(FailureRule):
    """
    Detects PVC mount failures after Pod scheduling, typically due to storage
    backend or node access issues.

    Signals:
    - Timeline contains FailedMount events
    - PVC object attached to Pod exists
    - Pod cannot start due to volume mount failure

    Interpretation:
    The Pod cannot mount its PersistentVolumeClaim because the underlying
    storage is inaccessible or misconfigured. This may be caused by node-level
    storage access issues, CSI driver failures, or storage backend unavailability.

    Scope:
    - Volume layer
    - Deterministic (event/timeline based)
    - Acts as a root cause for Pod startup failures related to volume mounts

    Exclusions:
    - Does not include PVC misconfiguration unrelated to mount
    - Does not include scheduling failures (covered by FailedScheduling)
    """

    name = "PVCMountFailed"
    category = "PersistentVolumeClaim"
    priority = 45
    phases = ["Pending", "Running"]

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return timeline_has_pattern(timeline, [{"reason": "FailedMount"}])

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        pvc_objs = context.get("objects", {}).get("pvc", {})
        pvc_name = next(iter(pvc_objs), "<unknown>")

        root_cause_msg = "Volume mount failed for PersistentVolumeClaim"

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PRESENT",
                    message=f"PVC '{pvc_name}' attached to Pod",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Kubelet failed to mount volume",
                    blocking=True,
                    role="volume_root",
                ),
                Cause(
                    code="CONTAINER_START_BLOCKED",
                    message="Pod cannot start containers",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.93,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Event: FailedMount",
                f"PVC {pvc_name} attached",
            ],
            "object_evidence": {f"pvc:{pvc_name}": ["Mount operation failed"]},
            "likely_causes": [
                "Node cannot access storage backend",
                "Storage backend unavailable",
                "CSI driver failure",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe pvc {pvc_name}",
                "kubectl describe node <node>",
            ],
        }
