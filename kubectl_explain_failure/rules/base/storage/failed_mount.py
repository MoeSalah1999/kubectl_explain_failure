from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class FailedMountRule(FailureRule):
    """
    Detects Pod failures to mount volumes due to unbound PVCs or unavailable storage.

    Signals:
    - Event reason == "FailedMount"
    - Timeline contains volume mount failure events
    - PVC not bound or storage backend unavailable

    Interpretation:
    The Pod cannot mount a required PersistentVolumeClaim. This prevents
    the container from starting, leaving the Pod in Pending or ContainerCreating
    state. The root cause can be a PVC that is not yet bound or a storage
    backend that is unavailable.

    Scope:
    - Volume provisioning and mounting layer
    - Deterministic (event-based)
    - Applies to Pods referencing PVCs

    Exclusions:
    - Does not include already bound PVCs
    - Does not include container runtime or filesystem errors unrelated to volume mount
    """

    name = "FailedMount"
    category = "PersistentVolumeClaim"
    priority = 40
    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }
    deterministic = True
    blocks = ["PVCNotBound", "VolumeUnavailable"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_pattern(timeline, [{"reason": "FailedMount"}])

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})
        pvc_name = next(iter(pvc_objs), "<unknown>")
        pvc = pvc_objs.get(pvc_name, {})

        # Determine root cause: PVC unbound vs storage backend
        if context.get("pvc_unbound"):
            root_cause_msg = "PersistentVolumeClaim not bound"
            root_cause_code = "PVC_NOT_BOUND"
            blocking = True
        else:
            root_cause_msg = (
                "Volume could not be provisioned or storage backend unavailable"
            )
            root_cause_code = "VOLUME_PROVISION_FAILED"
            blocking = True

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PRESENT",
                    message=f"PVC '{pvc_name}' is attached to the Pod",
                    role="volume_context",
                ),
                Cause(
                    code=root_cause_code,
                    message=root_cause_msg,
                    blocking=blocking,
                    role="volume_root",
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILURE",
                    message="Pod cannot mount the volume",
                    role="volume_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} attached",
                "Event: FailedMount",
            ],
            "object_evidence": {f"pvc:{pvc_name}": [root_cause_msg]},
            "likely_causes": [
                "PersistentVolumeClaim not bound",
                "Storage backend unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod.get('metadata', {}).get('name', '<pod>')}",
                f"kubectl get pvc {pvc_name}",
            ],
            "blocking": blocking,
        }
