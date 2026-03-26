from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIDriverNotFoundRule(FailureRule):
    """
    Detects Pods blocked due to missing CSI driver where:

    - The kubelet or attach/mount subsystem cannot find the required CSI driver
    - Volume operations fail because the driver is not registered
    - Failures repeat (not transient startup delay)

    Real-world interpretation:
    This occurs when:
    - CSI driver is not installed in the cluster
    - CSIDriver object is missing
    - CSI node plugin DaemonSet is not running on the node
    - Driver name in StorageClass / PV does not match installed driver

    Signals:
    - Repeated FailedMount / FailedAttachVolume events
    - Error messages referencing missing CSI driver
    - Sustained failures over time
    - No successful mount/attach observed

    Scope:
    - CSI / storage control plane
    - Node-level volume initialization
    - Blocking failure (Pod cannot start)

    Exclusions:
    - Transient driver startup delays
    - Generic mount failures without driver errors
    """

    name = "CSIDriverNotFound"
    category = "Storage"
    priority = 82

    phases = ["Pending", "ContainerCreating"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Look for relevant volume failure events ---
        recent_events = timeline.events_within_window(
            5, reason="FailedMount"
        ) + timeline.events_within_window(5, reason="FailedAttachVolume")

        if len(recent_events) < 3:
            return False

        # --- 2. Detect CSI driver missing semantics ---
        driver_missing_signals = 0
        for e in recent_events:
            msg = (e.get("message") or "").lower()

            if any(
                s in msg
                for s in [
                    "csi",
                    "driver",
                    "not found",
                    "no such driver",
                    "driver name",
                    "failed to find plugin",
                    "not registered",
                ]
            ):
                driver_missing_signals += 1

        if driver_missing_signals < 2:
            return False

        # --- 3. Ensure this is a volume failure domain ---
        if not timeline.has(kind="Volume", phase="Failure"):
            return False

        # --- 4. Sustained duration (avoid transient init race) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in ["FailedMount", "FailedAttachVolume"]
        )

        if duration < 45:
            return False

        # --- 5. No success signals ---
        if (
            timeline.count(reason="SuccessfulAttachVolume") > 0
            or timeline.count(reason="SuccessfulMountVolume") > 0
        ):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant error message (helps pinpoint driver name mismatch)
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in (
                    timeline.events_within_window(5, reason="FailedMount")
                    + timeline.events_within_window(5, reason="FailedAttachVolume")
                )
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_DRIVER_NOT_FOUND",
                    message="Required CSI driver is not available in the cluster",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_PLUGIN_UNREGISTERED",
                    message="CSI driver is not registered on the node or control plane",
                    role="volume_intermediate",
                ),
                Cause(
                    code="VOLUME_OPERATION_FAILURE",
                    message="Volume attach or mount operations cannot proceed",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_BLOCKED_ON_VOLUME",
                    message="Pod cannot start because volume initialization failed",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CSI driver required for volume is not installed or not registered",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Repeated volume operation failures (FailedMount / FailedAttachVolume)",
                "CSI driver not found or not registered in event messages",
                "Sustained failure duration (>45s)",
                "No successful volume attach or mount observed",
                *(["Dominant error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "CSI driver not installed in the cluster",
                "CSI node DaemonSet not running on target node",
                "Driver name mismatch between StorageClass and installed driver",
                "CSIDriver object missing or misconfigured",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get csidrivers",
                "kubectl get pods -A | grep csi",
                "kubectl describe node <node-name>",
                "Verify StorageClass provisioner matches installed CSI driver",
                "Check CSI controller and node plugin logs",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked due to missing CSI driver required for volume operations"
                ]
            },
        }
