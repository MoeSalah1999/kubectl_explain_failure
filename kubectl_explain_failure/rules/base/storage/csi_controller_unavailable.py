from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIControllerUnavailableRule(FailureRule):
    """
    Detects CSI control-plane unavailability.

    Real-world behavior:
    - controller-side outages show up most clearly in provisioning, attach,
      snapshot-restore, or expansion controller operations
    - generic node-local mount failures should not be enough on their own
    - explicit "driver not found" messages belong to CSIDriverNotFound
    """

    name = "CSIControllerUnavailable"
    category = "Storage"
    priority = 90
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "context": ["timeline"],
        "optional_objects": ["pvc", "storageclass"],
    }

    blocks = [
        "CSIProvisioningFailed",
        "VolumeAttachFailed",
        "VolumeExpansionFailed",
        "VolumeSnapshotRestoreFailed",
    ]

    CONTROLLER_FAILURE_REASONS = {
        "ProvisioningFailed",
        "FailedAttachVolume",
        "VolumeResizeFailed",
        "FailedCreate",
    }

    CONTROLLER_ERROR_MARKERS = (
        "rpc error",
        "connection refused",
        "context deadline exceeded",
        "deadline exceeded",
        "transport is closing",
        "timed out waiting for external provisioner",
        "timed out waiting for external-attacher",
        "no such host",
        "i/o timeout",
        "unavailable",
    )

    CONTROLLER_OPERATION_MARKERS = (
        "createvolume",
        "controllerpublishvolume",
        "controllerexpandvolume",
        "csi",
    )

    EXCLUSION_MARKERS = (
        "not found in the list of registered csi drivers",
        "failed to find plugin",
        "no such driver",
        "driver not registered",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _matches_event(self, event: dict) -> bool:
        if event.get("reason") not in self.CONTROLLER_FAILURE_REASONS:
            return False

        message = str(event.get("message", "")).lower()
        if any(marker in message for marker in self.EXCLUSION_MARKERS):
            return False

        has_error = any(marker in message for marker in self.CONTROLLER_ERROR_MARKERS)
        has_controller_context = any(
            marker in message for marker in self.CONTROLLER_OPERATION_MARKERS
        )
        return has_error and has_controller_context

    def _matching_events(self, timeline) -> list[dict]:
        return [event for event in timeline.raw_events if self._matches_event(event)]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        matched_events = self._matching_events(timeline)
        if not matched_events:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(lambda e: self._matches_event(e))

        if total_failures < 2 and duration < 60:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [
                (event.get("message") or "")
                for event in matched_events
                for _ in range(self._occurrences(event))
            ]
            dominant_msg = max(set(messages), key=messages.count)

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
                    message="CSI control-plane cannot process controller-side volume operations",
                    role="control_loop",
                ),
                Cause(
                    code="POD_BLOCKED_ON_STORAGE",
                    message="Pod cannot start because CSI-managed storage operations fail",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CSI controller is unavailable, causing controller-side volume operations to fail",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Controller-side volume lifecycle failures repeat over time",
                "Events show CSI controller RPC, timeout, or connection failures",
                *(["Dominant CSI error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "CSI controller pods are down or crash-looping",
                "CSI sidecars such as the provisioner, attacher, or resizer are not healthy",
                "Network or DNS issues prevent controller-to-driver communication",
                "Cloud provider API problems are causing CSI controller calls to fail",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get pods -n kube-system",
                "kubectl logs -n kube-system <csi-controller-pod>",
                "kubectl get volumeattachments",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked because CSI controller-side operations are unavailable"
                ]
            },
        }
