from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIDriverNotFoundRule(FailureRule):
    """
    Detects explicit CSI driver-name lookup failures.

    Real-world behavior:
    - this should only fire when the event text explicitly says the CSI driver
      is not found or not registered
    - a generic CSI timeout or RPC failure is not enough; those belong to more
      generic controller or attach failure rules
    """

    name = "CSIDriverNotFound"
    category = "Storage"
    priority = 82
    deterministic = True

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "CSIControllerUnavailable",
        "VolumeAttachFailed",
        "FailedMount",
        "PVCMountFailed",
    ]

    EXPLICIT_DRIVER_MARKERS = (
        "not found in the list of registered csi drivers",
        "failed to find plugin",
        "no such driver",
        "driver is not registered",
        "driver not registered",
        "csi driver not found",
    )

    def _matches_event(self, event: dict) -> bool:
        if event.get("reason") not in {"FailedMount", "FailedAttachVolume"}:
            return False

        message = str(event.get("message", "")).lower()
        if "csi" not in message and "driver" not in message:
            return False

        return any(marker in message for marker in self.EXPLICIT_DRIVER_MARKERS)

    def _matching_events(self, timeline) -> list[dict]:
        return [event for event in timeline.raw_events if self._matches_event(event)]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return bool(self._matching_events(timeline))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [(event.get("message") or "") for event in matched_events]
            dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_DRIVER_NOT_FOUND",
                    message="Required CSI driver name is not registered for volume operations",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_PLUGIN_UNAVAILABLE",
                    message="Kubelet or the attach path cannot resolve the requested CSI driver",
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
            "root_cause": "CSI driver required for the volume is not registered or cannot be found",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "FailedMount or FailedAttachVolume explicitly reports a missing CSI driver",
                *(["Dominant error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "CSI node plugin is not installed or not running on the target node",
                "StorageClass or PV references the wrong CSI driver name",
                "Driver registration on the node failed",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get csidrivers",
                "kubectl get pods -n kube-system",
                "Check CSI node plugin logs on the target node",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked because the requested CSI driver name cannot be resolved"
                ]
            },
        }
