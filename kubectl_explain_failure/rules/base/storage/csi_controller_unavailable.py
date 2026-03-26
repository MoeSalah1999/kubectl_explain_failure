from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIControllerUnavailableRule(FailureRule):
    """
    Detects failures caused by an unavailable or non-functional CSI controller where:

    - CSI controller (external-provisioner / attacher / resizer) is not responding
    - Volume operations (provision, attach, mount) fail at control-plane level
    - Errors persist over time (not transient API glitches)

    Real-world interpretation:
    This occurs when:
    - CSI controller pods are down or crash-looping
    - CSI sidecars (provisioner/attacher) are not running
    - API calls to CSI driver timeout or fail
    - Control-plane cannot process volume lifecycle operations

    Signals:
    - Repeated volume-related failures (ProvisioningFailed, FailedAttachVolume, FailedMount)
    - Error messages indicating RPC failure / timeout / connection issues
    - Sustained duration (retry loop)
    - No successful volume lifecycle events

    Scope:
    - CSI control-plane failure (cluster-level)
    - Affects multiple volume lifecycle stages
    - Blocking failure (prevents Pod startup)

    Exclusions:
    - Single transient volume failure
    - Node-local mount issues (handled by FailedMount rules)
    - PVC unbound (handled by PVC rules)
    """

    name = "CSIControllerUnavailable"
    category = "Storage"
    priority = 90

    phases = ["Pending", "ContainerCreating"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Detect repeated volume lifecycle failures (broad CSI signal) ---
        failure_reasons = [
            "ProvisioningFailed",
            "FailedAttachVolume",
            "FailedMount",
        ]

        recent_failures = []
        for r in failure_reasons:
            recent_failures.extend(timeline.events_within_window(5, reason=r))

        if len(recent_failures) < 4:
            return False

        # --- 2. Ensure failures are truly volume-related ---
        if not timeline.has(kind="Volume", phase="Failure"):
            return False

        # --- 3. CSI-specific error signatures (high-signal) ---
        csi_error_hits = 0
        for e in recent_failures:
            msg = (e.get("message") or "").lower()

            if any(
                kw in msg
                for kw in [
                    "rpc error",
                    "deadline exceeded",
                    "connection refused",
                    "timed out",
                    "csi",
                    "driver not found",
                    "no such host",
                ]
            ):
                csi_error_hits += 1

        if csi_error_hits < 2:
            return False

        # --- 4. Sustained retry duration ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in failure_reasons
        )

        if duration < 60:
            return False

        # --- 5. No success signals across lifecycle ---
        if (
            timeline.count(reason="SuccessfulAttachVolume") > 0
            or timeline.count(reason="ProvisioningSucceeded") > 0
        ):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        dominant_msg = None
        if timeline:
            msgs = []
            for r in ["ProvisioningFailed", "FailedAttachVolume", "FailedMount"]:
                msgs.extend(
                    [
                        (e.get("message") or "")
                        for e in timeline.events_within_window(5, reason=r)
                    ]
                )
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_CONTROLLER_UNAVAILABLE",
                    message="CSI controller is unavailable or not responding",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_CONTROL_PLANE_FAILURE",
                    message="CSI control-plane cannot process volume lifecycle operations",
                    role="control_loop",
                ),
                Cause(
                    code="VOLUME_OPERATION_FAILURE",
                    message="Volume provisioning/attach/mount operations repeatedly fail",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_BLOCKED_ON_STORAGE",
                    message="Pod cannot start due to failed CSI-managed volume operations",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CSI controller is unavailable, causing volume operations to fail",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Repeated volume lifecycle failures (provision/attach/mount)",
                "CSI-related RPC or timeout errors detected",
                "Sustained retry duration (>60s)",
                "No successful volume operations observed",
                *(["Dominant CSI error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "CSI controller pods are down or crash-looping",
                "CSI sidecar containers (provisioner/attacher) not running",
                "CSI driver not registered or misconfigured",
                "Network connectivity issues between controller and nodes",
                "Cloud provider API failures affecting CSI driver",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get pods -n kube-system | grep csi",
                "kubectl describe pods -n kube-system <csi-controller-pod>",
                "kubectl logs -n kube-system <csi-controller-pod>",
                "kubectl get csidrivers",
                "kubectl get volumeattachments",
                "Check cloud provider disk API health",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked due to CSI controller failing volume operations"
                ]
            },
        }
