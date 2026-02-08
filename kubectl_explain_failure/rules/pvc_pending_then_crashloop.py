from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCPendingThenCrashLoopRule(FailureRule):
    name = "PVCPendingThenCrashLoop"
    category = "Compound"
    priority = 50
    blocks = ["CrashLoopBackOff", "FailedMount"]
    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        timeline = context.get("timeline")
        if not pvc or not timeline:
            return False

        # PVC is pending and there is a repeating BackOff or FailedMount
        pvc_pending = pvc.get("status", {}).get("phase") == "Pending"
        crash_events = (
            timeline_has_pattern(timeline.raw_events, [{"reason": "FailedMount"}])
            and timeline_has_pattern(timeline.raw_events, [{"reason": "BackOff"}])
        )

        return pvc_pending and crash_events

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING",
                    message="PersistentVolumeClaim is Pending",
                    blocking=True,
                ),
                Cause(
                    code="FAILED_MOUNT",
                    message="Pod failed to mount volume",
                    blocking=True,
                ),
                Cause(
                    code="CRASHLOOP",
                    message="Containers repeatedly restarted",
                ),
            ]
        )

        pvc = context["blocking_pvc"]
        pvc_name = pvc["metadata"]["name"]

        return {
            "root_cause": "PVC Pending caused mount failures and CrashLoopBackOff",
            "confidence": 0.98,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} is Pending",
                "Repeated FailedMount / BackOff events observed",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}, phase:{pvc.get('status', {}).get('phase')}": [
                    "PVC not Bound"
                ]
            },
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "kubectl describe pod <name>",
                "Check storage backend / CSI controller health",
            ],
            "blocking": True,
        }
