from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule

class PVCPendingThenCrashLoopRule(FailureRule):
    """
    Detects Pods that experience CrashLoopBackOff following
    volume mount failures caused by a PersistentVolumeClaim
    remaining in Pending state.

    Signals:
    - PersistentVolumeClaim.status.phase is Pending
    - Pod events include FailedMount
    - Pod events include BackOff (CrashLoopBackOff)

    Interpretation:
    The PersistentVolumeClaim is not bound, preventing the
    kubelet from mounting the required volume. This blocks
    container initialization, which results in repeated
    startup attempts and eventual CrashLoopBackOff. The
    CrashLoop is a downstream symptom of a storage-layer
    binding failure.

    Scope:
    - Volume layer with execution propagation
    - Deterministic (object state + time-correlated events)
    - Acts as a compound suppression rule for simple
    CrashLoopBackOff and FailedMount signals

    Exclusions:
    - Does not include container crashes unrelated to volume usage
    - Does not include image pull failures
    - Does not include scheduling failures
    """
    name = "PVCPendingThenCrashLoop"
    category = "Compound"
    priority = 50
    blocks = ["CrashLoopBackOff", "FailedMount", "PVCMountFailed"]
    deterministic = True
    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        timeline = context.get("timeline")
        if not pvc or not timeline:
            return False

        # PVC is pending
        pvc_pending = pvc.get("status", {}).get("phase") == "Pending"

        # Use events_within_window for CrashLoop/FailedMount detection
        failed_mount_events = timeline.events_within_window(minutes=30, reason="FailedMount")
        backoff_events = timeline.events_within_window(minutes=30, reason="BackOff")

        crash_events_present = bool(failed_mount_events) and bool(backoff_events)

        return pvc_pending and crash_events_present

    def explain(self, pod, events, context):
        pvc = context.get("blocking_pvc")
        pvc_name = pvc["metadata"]["name"] if pvc else "unknown"
        
        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING_CONTEXT",
                    message=f"PersistentVolumeClaim {pvc_name} is Pending",
                    role="volume_context",
                ),
                Cause(
                    code="PVC_BINDING_BLOCKED",
                    message="PersistentVolumeClaim is not bound, preventing volume attachment",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_MOUNT_FAILED",
                    message="Kubelet failed to mount required volume",
                    role="execution_intermediate",
                ),
                Cause(
                    code="CONTAINER_CRASH_LOOP",
                    message="Container repeatedly restarted due to missing volume dependency",
                    role="container_health_root",
                ),
                Cause(
                    code="POD_NOT_READY",
                    message="Pod cannot reach Ready state due to repeated container restarts",
                    role="workload_symptom",
                ),
            ]
        )

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