from datetime import datetime

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import parse_time


class VolumeAttachDetachThrashingRule(FailureRule):
    """
    Detects repeated short-window attach/detach alternation, for example:

    Attach -> Detach -> Attach -> Detach
    """

    name = "VolumeAttachDetachThrashing"
    category = "Temporal"
    priority = 90
    deterministic = False
    blocks = [
        "FailedMount",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    ATTACH_MARKERS = (
        "successfulattachvolume",
        "attachvolume.attach",
        "attached volume",
        "volume successfully attached",
        "attaching volume",
    )
    DETACH_MARKERS = (
        "detaching volume",
        "detached volume",
        "volume successfully detached",
        "deleting volumeattachment",
        "volumeattachment deleted",
    )
    EXCLUSION_MARKERS = (
        "already attached",
        "already exclusively attached",
        "multi-attach",
    )

    MIN_SEQUENCE_LENGTH = 4
    MAX_WINDOW_SECONDS = 900
    MIN_WINDOW_SECONDS = 60

    def _extract_timestamp(self, event: dict) -> datetime | None:
        timestamp = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not timestamp:
            return None
        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _classify_event(self, event: dict) -> str | None:
        reason = str(event.get("reason", "")).lower()
        message = str(event.get("message", "")).lower()

        if any(marker in message for marker in self.EXCLUSION_MARKERS):
            return None

        if reason in {"successfulattachvolume", "failedattachvolume"}:
            return "attach"

        if "detach" in reason:
            return "detach"

        if any(marker in message for marker in self.ATTACH_MARKERS):
            return "attach"
        if any(marker in message for marker in self.DETACH_MARKERS):
            return "detach"

        return None

    def _typed_events(self, timeline) -> list[tuple[datetime, str]]:
        typed: list[tuple[datetime, str]] = []
        for event in timeline.raw_events:
            timestamp = self._extract_timestamp(event)
            event_type = self._classify_event(event)
            if timestamp is None or event_type is None:
                continue
            typed.append((timestamp, event_type))

        typed.sort(key=lambda item: item[0])
        return typed

    def _alternating_sequence(
        self, typed_events: list[tuple[datetime, str]]
    ) -> list[str]:
        sequence: list[str] = []
        for _, event_type in typed_events:
            if not sequence or sequence[-1] != event_type:
                sequence.append(event_type)
        return sequence

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        typed_events = self._typed_events(timeline)
        if len(typed_events) < self.MIN_SEQUENCE_LENGTH:
            return False

        sequence = self._alternating_sequence(typed_events)
        if len(sequence) < self.MIN_SEQUENCE_LENGTH:
            return False

        if sequence[:4] not in (
            ["attach", "detach", "attach", "detach"],
            ["detach", "attach", "detach", "attach"],
        ):
            return False

        duration = (typed_events[-1][0] - typed_events[0][0]).total_seconds()
        if duration < self.MIN_WINDOW_SECONDS or duration > self.MAX_WINDOW_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_DRIVER_OR_NODE_ISSUE",
                    message="Underlying CSI driver bugs or node-level attach/detach errors are causing volume flapping",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_ATTACH_DETACH_FLAPPING",
                    message="Volume repeatedly attaches and detaches within a short time window",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_VOLUME_INSTABILITY",
                    message="Pod is affected by unstable volume lifecycle transitions",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod is impacted by repeated volume attach and detach cycles"
            ]
        }
        for pvc_name in context.get("objects", {}).get("pvc", {}):
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC is involved in repeated short-window attach and detach events"
            ]

        return {
            "root_cause": "Pod is impacted by flapping volume attach and detach behavior",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Timeline shows an alternating attach/detach/attach/detach pattern",
                "The attach and detach cycle repeats within a short time window",
            ],
            "likely_causes": [
                "CSI driver bug causing flapping volume attachments",
                "Node-level instability or repeated controller retries",
                "Backend attachment state is oscillating instead of converging",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl get volumeattachments",
                "Inspect CSI controller and node plugin logs",
                "Check node health and storage backend attachment state",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
