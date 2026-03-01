from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class DynamicProvisioningTimeoutRule(FailureRule):
    """
    Detects PersistentVolumeClaims that remain Pending due to
    dynamic provisioning repeatedly retrying and exceeding a
    defined timeout threshold.

    Signals:
    - PVC.status.phase is Pending
    - Repeated provisioning-related events observed
    - Provisioning duration exceeds configured timeout

    Interpretation:
    The dynamic volume provisioner is repeatedly attempting to
    create a PersistentVolume but is unable to complete the
    operation successfully. The sustained retry behavior over
    a bounded duration indicates a provisioning failure rather
    than a transient delay.

    Scope:
    - Volume layer (dynamic provisioning lifecycle)
    - Deterministic (object state + timeline duration)
    - Acts as a temporal escalation rule for provisioning stalls

    Exclusions:
    - Does not include statically provisioned volumes
    - Does not include PVCs blocked by Node pressure
    - Does not include PVs in Released or Failed states
    """

    name = "DynamicProvisioningTimeout"
    category = "PersistentVolumeClaim"
    priority = 58
    blocks = ["PVCBoundNodePressure", "PVReleasedOrFailed"]
    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }
    phases = ["Pending"]

    TIMEOUT_SECONDS = 600  # 10 minutes

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        pvcs = objects.get("pvc", {})
        if not pvcs:
            return False

        pvc = next(iter(pvcs.values()))
        if pvc.get("status", {}).get("phase") != "Pending":
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect repeated provisioning attempts
        duration = timeline.duration_between(
            lambda e: "provisioning" in (e.get("message") or "").lower()
        )

        return duration >= self.TIMEOUT_SECONDS

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_name = next(iter(objects.get("pvc", {})), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="DYNAMIC_PROVISIONING_STALLED",
                    message="Dynamic volume provisioner repeatedly failed to create volume",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="PROVISIONING_RETRY_DURATION_EXCEEDED",
                    message=f"Provisioning attempts exceeded {self.TIMEOUT_SECONDS} second threshold",
                    role="volume_intermediate",
                ),
                Cause(
                    code="PVC_REMAINS_PENDING",
                    message="PersistentVolumeClaim remains Pending due to provisioning stall",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PVC cannot be provisioned due to dynamic provisioning timeout",
            "confidence": 0.97,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} phase = Pending",
                "Repeated provisioning events detected",
                "Provisioning duration exceeded timeout threshold",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": ["Dynamic provisioning timeout observed"],
            },
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "Check StorageClass provisioner logs",
                "Verify cloud provider capacity/quotas",
            ],
            "blocking": True,
        }
