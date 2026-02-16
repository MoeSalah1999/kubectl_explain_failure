from kubectl_explain_failure.timeline import parse_time
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule



class DynamicProvisioningTimeoutRule(FailureRule):
    """
    PVC Pending
    → Repeated provisioning attempts
    → Time exceeds threshold
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
        provisioning_events = [
            e for e in timeline.raw_events
            if "provisioning" in e.get("message", "").lower()
        ]

        if len(provisioning_events) < 2:
            return False

        # Time threshold check
        try:
            first_ts = provisioning_events[0].get("firstTimestamp")
            last_ts = provisioning_events[-1].get("lastTimestamp")

            if not first_ts or not last_ts:
                return False

            duration = (
                parse_time(last_ts) - parse_time(first_ts)
            ).total_seconds()

            return duration >= self.TIMEOUT_SECONDS

        except Exception:
            return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_name = next(iter(objects.get("pvc", {})), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PENDING",
                    message="PersistentVolumeClaim remains Pending",
                    blocking=True,
                    role="storage_root",
                ),
                Cause(
                    code="PROVISIONING_RETRY_LOOP",
                    message="Provisioner repeatedly attempts volume creation",
                    blocking=True,
                    role="provisioning_intermediate",
                ),
                Cause(
                    code="PROVISIONING_TIMEOUT",
                    message="Provisioning exceeded acceptable time threshold",
                    role="temporal_escalation",
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