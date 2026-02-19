
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import events_within


class PVCPendingTooLongRule(FailureRule):
    name = "PVCPendingTooLong"
    category = "PersistentVolumeClaim"
    priority = 20  # higher than basic PVC pending
    blocks = ["PVCNotBound", "FailedScheduling"]

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        if not pvc:
            return False

        phase = pvc.get("status", {}).get("phase")
        if phase != "Pending":
            return False

        recent = events_within(context["timeline"].raw_events, minutes=30)
        return len(recent) > 10  # sustained failure

    def explain(self, pod, events, context):
        pvc = context.get("blocking_pvc")
        pvc_name = pvc["metadata"]["name"] if pvc else "unknown"
        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING",
                    message="PersistentVolumeClaim has been Pending",
                    blocking=True,
                ),
                Cause(
                    code="PROVISIONING_DELAY",
                    message="Volume provisioning has not completed in a reasonable time",
                ),
                Cause(
                    code="STORAGE_BACKEND_FAILURE",
                    message="Storage backend or provisioner is likely unhealthy",
                ),
            ]
        )
        return {
            "root_cause": "PersistentVolumeClaim provisioning is stalled",
            "confidence": 0.97,
            "causes": chain,
            "evidence": ["PVC Pending for >30 minutes"],
            "object_evidence": {
                f"pvc:{pvc_name}, phase:{pvc.get('status', {}).get('phase')}": [
                    "PVC not Bound"
                ]
            },
            "suggested_checks": [
                "Check StorageClass provisioner logs",
                "Verify cloud storage quota",
                "Inspect CSI controller health",
            ],
            "blocking": True,
        }
