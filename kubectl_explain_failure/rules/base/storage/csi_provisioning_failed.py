from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIProvisioningFailedRule(FailureRule):
    """
    Detects failures in dynamic volume provisioning via CSI drivers.

    Real-world scenarios:
    - StorageClass misconfiguration (invalid parameters)
    - CSI driver unavailable or crashing
    - Backend storage system rejecting volume creation
    - Quota / capacity exhaustion in storage backend
    - Authentication / permission failures in CSI provisioner

    Signals:
    - ProvisioningFailed / ExternalProvisioning events on PVC
    - Repeated provisioning attempts without success
    - CSI-related error messages (CreateVolume, rpc error, etc.)
    - PVC remains in Pending phase

    Scope:
    - PersistentVolumeClaim provisioning lifecycle
    - Deterministic when explicit provisioning failures are observed
    """

    name = "CSIProvisioningFailed"
    category = "PersistentVolumeClaim"
    priority = 95
    deterministic = True

    blocks = [
        "PVCUnbound",
        "VolumeProvisioningDelayed",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        pvc_objects = context.get("objects", {}).get("pvc", {})
        if not pvc_objects:
            return False

        # --- 1. PVC must still be unbound ---
        unbound = False
        for pvc in pvc_objects.values():
            status = pvc.get("status")
            phase = None

            if isinstance(status, dict):
                phase = status.get("phase")
            elif isinstance(status, str):
                phase = status

            if phase != "Bound":
                unbound = True
                break

        if not unbound:
            return False

        # --- 2. Recent provisioning failure signals ---
        recent_failures = timeline.events_within_window(
            10, reason="ProvisioningFailed"
        ) + timeline.events_within_window(10, reason="ExternalProvisioning")

        if len(recent_failures) < 2:
            return False

        # --- 3. Detect CSI-specific failure semantics ---
        failure_signals = 0

        for e in recent_failures:
            msg = (e.get("message") or "").lower()

            if (
                "failed to provision volume" in msg
                or "createvolume" in msg
                or "rpc error" in msg
                or "timed out waiting for external provisioner" in msg
                or "no matches for kind" in msg
                or "storageclass" in msg
                or "not found" in msg
                or "permission denied" in msg
                or "quota" in msg
                or "exceeded" in msg
            ):
                failure_signals += 1

        if failure_signals < 2:
            return False

        # --- 4. Ensure no successful provisioning occurred ---
        if timeline.count(reason="ProvisioningSucceeded") > 0:
            return False

        # --- 5. Ensure it's not just slow provisioning ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in ("ProvisioningFailed", "ExternalProvisioning")
        )

        if duration < 30:  # avoid transient retries
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        pvc_objects = context.get("objects", {}).get("pvc", {})
        pvc_name = "<unknown>"

        if pvc_objects:
            pvc_obj = next(iter(pvc_objects.values()))
            pvc_name = pvc_obj.get("metadata", {}).get("name", "<unknown>")

        timeline = context.get("timeline")

        # Extract dominant provisioning error
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(10)
                if e.get("reason") in ("ProvisioningFailed", "ExternalProvisioning")
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_PROVISIONING_FAILURE",
                    message="CSI driver failed to provision a volume",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_UNBOUND",
                    message="PersistentVolumeClaim remains unbound due to provisioning failure",
                    role="storage_intermediate",
                ),
                Cause(
                    code="POD_VOLUME_BLOCKED",
                    message="Pod cannot start because required volume is not available",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PVC cannot be provisioned due to CSI driver or storage backend failure",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Repeated ProvisioningFailed or ExternalProvisioning events",
                "CSI provisioning error messages detected",
                "PVC remains in Pending (unbound) state",
                "Provisioning retries sustained over time (>30s)",
                *(
                    ["Dominant provisioning error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver is not running or misconfigured",
                "StorageClass parameters are invalid",
                "Backend storage system rejected volume creation",
                "Insufficient storage capacity or quota exceeded",
                "Permission or authentication failure in CSI provisioner",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                f"kubectl describe pod {pod_name}",
                "kubectl get storageclass",
                "kubectl get events --sort-by=.lastTimestamp",
                "Check CSI controller pods (kubectl get pods -n kube-system)",
                "Inspect CSI driver logs",
                "Verify StorageClass parameters",
                "Check backend storage system health and quotas",
            ],
            "blocking": True,
            "object_evidence": {
                f"pvc:{pvc_name}": [
                    "PVC stuck in Pending due to repeated provisioning failures"
                ],
                f"pod:{pod_name}": [
                    "Pod blocked waiting for dynamically provisioned volume"
                ],
            },
        }
