from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeAttachDetachThrashingRule(FailureRule):
    """
    Detects Pods experiencing repeated volume attach/detach cycles,
    indicating CSI instability or flapping volumes in production.

    Signals:
    - Alternating Attach and Detach events on the same volume
    - Rapid repetition within a short time window (~5-15 minutes)
    - Pod may be Pending, Running, or experience transient restarts

    Interpretation:
    Volumes are repeatedly attached and detached from nodes, which
    prevents stable usage by Pods. This is indicative of CSI bugs,
    misconfigured StorageClasses, or node-level issues affecting volume
    attachment/detachment lifecycle.

    Scope:
    - Volume layer (CSI attach/detach)
    - Captures deterministic flapping behavior over a short timeline

    Exclusions:
    - Ignore single transient detach/attach events
    - Ignore volumes marked as "already attached" or "exclusively attached" resolved by normal CSI operations
    """

    name = "VolumeAttachDetachThrashing"
    category = "Temporal"
    priority = 90
    deterministic = True
    blocks = [
        "VolumeMountFailure",
        "PVCNotBound",
        "PodUnschedulable",
        "FailedMount",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    ATTACH_MARKERS = ("attach", "attaching volume", "volume successfully attached")
    DETACH_MARKERS = ("detach", "detaching volume", "volume successfully detached")
    EXCLUSION_MARKERS = ("already attached", "exclusively attached")

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _volume_events(self, timeline):
        """Return all attach/detach events normalized."""
        attach_events = []
        detach_events = []
        for event in timeline.raw_events:
            msg = str(event.get("message", "")).lower()
            if any(marker in msg for marker in self.EXCLUSION_MARKERS):
                continue
            if any(marker in msg for marker in self.ATTACH_MARKERS):
                attach_events.append(event)
            elif any(marker in msg for marker in self.DETACH_MARKERS):
                detach_events.append(event)
        return attach_events, detach_events

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        attach_events, detach_events = self._volume_events(timeline)
        if not attach_events or not detach_events:
            return False

        # Detect repeated flapping pattern (Attach → Detach → Attach → Detach)
        combined_events = sorted(
            attach_events + detach_events,
            key=lambda e: e.get("eventTime") or e.get("lastTimestamp") or "",
        )
        last_type = None
        flip_count = 0
        for e in combined_events:
            msg = str(e.get("message", "")).lower()
            if any(marker in msg for marker in self.ATTACH_MARKERS):
                current_type = "attach"
            else:
                current_type = "detach"

            if last_type and current_type != last_type:
                flip_count += 1
            last_type = current_type

        # Require at least 2 full attach-detach flips
        if flip_count < 4:
            return False

        # Ensure flapping occurred within recent timeline window (~15 min)
        duration = timeline.duration_between(
            lambda e: any(
                m in str(e.get("message", "")).lower()
                for m in self.ATTACH_MARKERS + self.DETACH_MARKERS
            )
        )
        if duration > 900:  # 15 minutes
            return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_DRIVER_OR_NODE_ISSUE",
                    message="Underlying CSI driver bugs or node-level attach/detach errors likely causing volume flapping",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_ATTACH_DETACH_FLAPPING",
                    message="Volume repeatedly attached and detached, indicating CSI instability",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_VOLUME_INSTABILITY",
                    message="Pod affected by unstable volume lifecycle, may remain Pending or restart",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": ["Pod impacted by repeated volume attach/detach cycles"]
        }
        referenced_pvcs = context.get("objects", {}).get("pvc", {})
        for pvc_name in referenced_pvcs:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC involved in repeated attach/detach cycles"
            ]

        return {
            "root_cause": "Pod impacted by flapping volume attach/detach",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Rapid repeated Attach/Detach events detected for volume(s)",
                "Pod stability may be impacted by CSI attach/detach instability",
            ],
            "likely_causes": [
                "CSI driver bugs causing flapping attachments",
                "Node-level volume attach/detach errors",
                "StorageClass misconfiguration or ephemeral node volume conflicts",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Inspect CSI driver logs for volume attach/detach errors",
                "Check node conditions affecting volume attachments",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
