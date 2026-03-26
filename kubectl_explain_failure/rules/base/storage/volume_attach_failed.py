from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeAttachFailedRule(FailureRule):
    """
    Detects repeated volume attach failures after a Pod has already been
    scheduled to a node.

    Real-world behavior:
    - looks specifically for `FailedAttachVolume`
    - excludes explicit multi-attach / device-conflict wording, which is a
      more specific root cause handled elsewhere
    - tolerates Kubernetes event aggregation via `count`
    """

    name = "VolumeAttachFailed"
    category = "Storage"
    priority = 80

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    CONFLICT_MARKERS = (
        "multi-attach error",
        "already attached",
        "already exclusively attached",
        "exclusively attached",
        "device is busy",
        "device or resource busy",
        "mount point busy",
        "volume mode",
        "raw block",
        "block device",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_generic_attach_failure(self, event: dict) -> bool:
        if event.get("reason") != "FailedAttachVolume":
            return False

        message = str(event.get("message", "")).lower()
        return not any(marker in message for marker in self.CONFLICT_MARKERS)

    def _matching_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if self._is_generic_attach_failure(event)
        ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not pod.get("spec", {}).get("nodeName") and not any(
            event.get("reason") == "Scheduled" for event in timeline.raw_events
        ):
            return False

        matched_events = self._matching_events(timeline)
        if not matched_events:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: self._is_generic_attach_failure(e)
        )

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
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_ATTACH_FAILED",
                    message="Volume cannot be attached to the target node",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="ATTACH_CONTROLLER_RETRY",
                    message="AttachDetach controller repeatedly retries volume attachment",
                    role="control_loop",
                ),
                Cause(
                    code="VOLUME_UNAVAILABLE_ON_NODE",
                    message="Volume not available on node, preventing container startup",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_BLOCKED_ON_VOLUME",
                    message="Pod cannot start because required volume is not attached",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Volume attachment to node is failing, blocking Pod startup",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "FailedAttachVolume events persist for the scheduled Pod",
                "Attach failures are not classified as explicit multi-attach or device conflicts",
                *(["Dominant attach error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "Cloud provider failed to attach disk (quota, API error, or timeout)",
                "Node is not reachable or not ready for volume attachment",
                "Zone or topology mismatch between node and volume",
                "CSI attacher or backend keeps timing out",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe node <node-name>",
                "kubectl describe pvc",
                "kubectl get volumeattachments",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked waiting for volume attachment to complete"
                ]
            },
        }
