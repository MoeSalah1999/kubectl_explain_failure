from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class VolumeAttachmentTimeoutRule(FailureRule):
    """
    Detects PVCs that are Bound but the underlying volume attachment
    is delayed beyond expected thresholds.

    Signals:
    - PVC.status.phase == Bound
    - VolumeAttachment took unusually long
    - Event timeline shows attachment failure/delay

    Interpretation:
    The PVC is technically bound but the underlying storage volume
    is not attached or acknowledged by the node, which can block
    pod scheduling or container startup.

    Scope:
    - Storage-level failure
    - Deterministic (based on PVC + event timeline)
    """

    name = "VolumeAttachmentTimeout"
    category = "Temporal"
    priority = 60
    deterministic = True
    blocks = []
    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        pvc_objects = context.get("objects", {}).get("pvc", {})

        if not timeline or not pvc_objects:
            return False

        # Check PVCs in Bound state
        for pvc in pvc_objects.values():
            phase = pvc.get("status", {}).get("phase")
            if phase != "Bound":
                continue

            # Look for delayed volume attachment events
            if timeline_has_event(
                timeline,
                kind="Volume",
                phase="Failure",
                source="AttachVolume",
            ):
                return True

        return False

    def explain(self, pod, events, context):
        pvc_objects = context.get("objects", {}).get("pvc", {})
        pvc_names = list(pvc_objects.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND",
                    message="PVC is in Bound state",
                    role="storage_context",
                ),
                Cause(
                    code="VOLUME_ATTACHMENT_DELAYED",
                    message="Underlying volume attachment is taking too long",
                    role="storage_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SCHEDULE_BLOCKED",
                    message="Pod cannot start due to pending volume attachment",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PVC is Bound but volume attachment is delayed",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"PVCs: {', '.join(pvc_names)}",
                "Timeline indicates volume attachment delays",
            ],
            "object_evidence": {
                f"pvc:{name}": ["Volume attachment delayed"] for name in pvc_names
            },
            "likely_causes": [
                "Storage backend latency or failure",
                "Node not acknowledging volume attachment",
                "Kubernetes controller processing delay",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {name}" for name in pvc_names
            ],
        }