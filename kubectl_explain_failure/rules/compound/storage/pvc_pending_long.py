from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCPendingTooLongRule(FailureRule):
    """
    Detects PersistentVolumeClaims that remain in Pending
    state for an extended period, indicating stalled
    provisioning and preventing dependent Pods from starting.

    Signals:
    - PersistentVolumeClaim.status.phase is Pending
    - PVC remains Pending beyond an acceptable time window
    - Sustained events observed during the Pending period

    Interpretation:
    The PersistentVolumeClaim has not successfully bound
    within a reasonable timeframe. This indicates a storage
    provisioning stall, typically caused by an unhealthy
    CSI provisioner, misconfigured StorageClass, quota
    exhaustion, or backend infrastructure failure. The
    unresolved PVC blocks volume attachment and prevents
    Pods from progressing to startup.

    Scope:
    - Volume layer (provisioning stage)
    - Deterministic (object state + time window correlation)
    - Acts as an escalation rule for prolonged PVC Pending states

    Exclusions:
    - Does not include transient Pending states
    - Does not include mount failures after successful binding
    - Does not include container runtime crashes
    """
    name = "PVCPendingTooLong"
    category = "PersistentVolumeClaim"
    priority = 23
    blocks = ["PVCNotBound", "FailedScheduling"]

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        timeline = context.get("timeline")
        if not pvc or not timeline:
            return False

        phase = pvc.get("status", {}).get("phase")
        if phase != "Pending":
            return False

        recent_events = timeline.events_within_window(minutes=30)
        return len(recent_events) > 6  # sustained failure

    def explain(self, pod, events, context):
        pvc = context.get("blocking_pvc")
        pvc_name = pvc["metadata"]["name"] if pvc else "unknown"

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING_CONTEXT",
                    message=f"PersistentVolumeClaim {pvc_name} remains Pending",
                    role="volume_context",
                ),
                Cause(
                    code="PVC_PROVISIONING_STALLED",
                    message="PersistentVolumeClaim provisioning has exceeded acceptable duration",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STARTUP_GATED_BY_PVC",
                    message="Pod startup is blocked by unresolved volume binding",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod cannot progress due to unbound PersistentVolumeClaim",
                    role="workload_symptom",
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