from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class VolumeAttachmentStuckRule(FailureRule):
    """
    Detects workloads blocked by a VolumeAttachment that is stuck in the
    attach/detach workflow.

    Real-world behavior:
    --------------------
    Kubernetes CSI drivers create VolumeAttachment objects whenever a volume
    must be attached to a node before mount.

    Common production failures:

    - attachdetach-controller repeatedly fails AttachVolume
    - VolumeAttachment status.attached never becomes True
    - CSI attacher sidecar unavailable
    - cloud provider attach API failures
    - stale VolumeAttachment referencing a dead node
    - multi-attach conflicts
    - detach never completes after node loss
    - volume remains attached to another node
    - CSI controller reports timeout / deadline exceeded

    Typical symptoms:

    - Pod remains Pending or ContainerCreating
    - FailedAttachVolume events
    - AttachVolume.Attach failed messages
    - Multi-Attach errors
    - Mount never begins because attachment never succeeds

    Exclusions:

    - mount failures after successful attachment
    - filesystem corruption
    - PVC provisioning failures
    - snapshot/resize failures
    """

    name = "VolumeAttachmentStuck"
    category = "Storage"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "volumeattachment",
            "pod",
            "node",
            "persistentvolume",
        ],
    }

    blocks = [
        "FailedMount",
        "CSINodePublishVolumeFailed",
        "VolumeMountTimeout",
    ]

    WINDOW_MINUTES = 60

    ATTACH_FAILURE_MARKERS = (
        "failedattachvolume",
        "attachvolume.attach failed",
        "attach volume",
        "timed out waiting for the condition",
        "volume attachment is being deleted",
        "multi-attach error",
        "multi attach error",
        "volume is already attached",
        "volume attachment failed",
        "rpc error",
        "deadline exceeded",
        "could not attach volume",
        "attachment timeout",
        "attach timeout",
    )

    ATTACH_PENDING_MARKERS = (
        "attachvolume",
        "failedattachvolume",
        "volumeattachment",
        "volume attachment",
        "attach volume",
    )

    CSI_ATTACHER_IDENTIFIERS = (
        "external-attacher",
        "csi-attacher",
        "external attacher",
    )

    CSI_ATTACHER_FAILURE_MARKERS = (
        "crashloopbackoff",
        "leader election lost",
        "failed to sync",
        "rpc error",
        "deadline exceeded",
        "connection refused",
        "timed out",
        "panic",
        "permission denied",
    )

    CSI_ATTACHER_WAITING_REASONS = {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerError",
        "CreateContainerConfigError",
        "RunContainerError",
        "ContainerCannotRun",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None

        try:
            return parse_time(raw)
        except Exception:
            return None

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _identity_text(self, obj: dict[str, Any]) -> str:
        metadata = obj.get("metadata", {}) or {}
        labels = metadata.get("labels", {}) or {}

        values = [
            str(metadata.get("name") or ""),
            str(metadata.get("namespace") or ""),
        ]

        values.extend(f"{k}={v}" for k, v in labels.items())

        spec = obj.get("spec", {}) or {}
        status = obj.get("status", {}) or {}

        for container in (
            spec.get("containers", [])
            + spec.get("initContainers", [])
            + status.get("containerStatuses", [])
        ):
            if isinstance(container, dict):
                values.append(str(container.get("name") or ""))

        return " ".join(values).lower()

    def _is_attacher_object(self, obj: dict[str, Any]) -> bool:
        text = self._identity_text(obj)

        return any(ident in text for ident in self.CSI_ATTACHER_IDENTIFIERS)

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        conditions = pod_obj.get("status", {}).get("conditions", []) or []

        return any(
            c.get("type") == "Ready" and c.get("status") == "True" for c in conditions
        )

    def _degraded_attacher_pods(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        degraded = []

        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if not isinstance(pod_obj, dict):
                continue

            if not self._is_attacher_object(pod_obj):
                continue

            status = pod_obj.get("status", {}) or {}

            if status.get("phase") not in {"Running", "Succeeded"}:
                degraded.append(pod_obj)
                continue

            if not self._pod_ready(pod_obj):
                degraded.append(pod_obj)
                continue

            for container in status.get("containerStatuses", []) or []:
                state = container.get("state", {}) or {}

                waiting = state.get("waiting", {}) or {}
                terminated = state.get("terminated", {}) or {}

                if waiting.get("reason") in self.CSI_ATTACHER_WAITING_REASONS:
                    degraded.append(pod_obj)
                    break

                if terminated and int(terminated.get("exitCode", 0) or 0) != 0:
                    degraded.append(pod_obj)
                    break

        return degraded

    def _volume_attachment_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        attachments = context.get("objects", {}).get("volumeattachment", {})

        for attachment in attachments.values():
            if not isinstance(attachment, dict):
                continue

            status = attachment.get("status", {}) or {}

            attached = status.get("attached")

            if attached is False:
                attach_error = status.get("attachError", {}) or {}

                message = attach_error.get("message") or attach_error.get("errorCode")

                return (
                    attachment,
                    (
                        str(message)
                        if message
                        else "VolumeAttachment exists but attached=False"
                    ),
                )

        return None, None

    def _attachment_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.ATTACH_PENDING_MARKERS):
                matches.append(event)

        return matches

    def _attach_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.ATTACH_FAILURE_MARKERS):
                failures.append(event)

        return failures

    def _attacher_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(ident in text for ident in self.CSI_ATTACHER_IDENTIFIERS) and any(
                marker in text for marker in self.CSI_ATTACHER_FAILURE_MARKERS
            ):
                failures.append(event)

        return failures

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        attachment_obj, attachment_signal = self._volume_attachment_signal(context)

        attachment_events = self._attachment_events(timeline)

        attach_failures = self._attach_failure_events(timeline)

        if not attachment_signal and not attach_failures:
            return None

        degraded_attacher_pods = self._degraded_attacher_pods(context)

        attacher_failures = self._attacher_failure_events(timeline)

        object_evidence: dict[str, list[str]] = {}
        signals: list[str] = []

        if attachment_obj and attachment_signal:
            name = self._object_name(attachment_obj)

            object_evidence[f"volumeattachment:{name}"] = [attachment_signal]

            signals.append(attachment_signal)

        for pod_obj in degraded_attacher_pods[:3]:
            pod_name = self._object_name(pod_obj)

            object_evidence[f"pod:{pod_name}"] = [
                "CSI external-attacher pod is degraded"
            ]

            signals.append(
                f"CSI external-attacher pod {pod_name} is not Ready or failing"
            )

        if attacher_failures:
            latest = self._message(attacher_failures[-1])

            object_evidence.setdefault(
                "timeline:csi-attacher",
                [],
            ).append(latest)

            signals.append(f"Recent CSI attacher failure event: {latest}")

        if attach_failures:
            signals.append(self._message(attach_failures[-1]))

        if (
            not attachment_signal
            and not degraded_attacher_pods
            and not attacher_failures
        ):
            return None

        return {
            "attachment_events": attachment_events,
            "attach_failures": attach_failures,
            "signals": list(dict.fromkeys(signals)),
            "object_evidence": object_evidence,
            "attacher_failures": attacher_failures,
        }

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(
                timeline,
                Timeline,
            )
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        if not isinstance(
            timeline,
            Timeline,
        ):
            raise ValueError("VolumeAttachmentStuck requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("VolumeAttachmentStuck explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        attach_occurrences = sum(
            self._occurrences(e) for e in candidate["attach_failures"]
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_REQUIRES_NODE_ATTACHMENT",
                    message="The workload volume must be attached before mount can begin",
                    role="runtime_context",
                ),
                Cause(
                    code="VOLUME_ATTACHMENT_STUCK",
                    message="The CSI volume attachment workflow is unable to complete",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CANNOT_MOUNT_VOLUME",
                    message="Volume mount cannot proceed because attachment never completed",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} is waiting on storage attachment operations",
            (
                f"Observed {attach_occurrences} volume attachment "
                "failure occurrence(s) during the incident window"
            ),
        ]

        evidence.extend(candidate["signals"])

        confidence = 0.94

        if candidate["attacher_failures"] and candidate["object_evidence"]:
            confidence = 0.98
        elif candidate["object_evidence"]:
            confidence = 0.97

        return {
            "rule": self.name,
            "root_cause": (
                "VolumeAttachment is stuck and storage attachment cannot complete"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v))
                for k, v in candidate["object_evidence"].items()
            },
            "likely_causes": [
                "The volume remains attached to another node (Multi-Attach conflict)",
                "The CSI external-attacher controller is unavailable or unhealthy",
                "Cloud-provider or storage backend attachment APIs are failing",
                "A stale VolumeAttachment references a lost or deleted node",
                "The attach/detach controller cannot reconcile attachment state",
                "CSI controller communication is timing out or returning RPC errors",
            ],
            "suggested_checks": [
                "kubectl get volumeattachment",
                "kubectl describe volumeattachment <attachment>",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get pods -A | grep attacher",
                "kubectl logs <csi-attacher-pod>",
                "kubectl describe pod <affected-pod>",
                "kubectl describe node <node>",
                "Verify whether the volume is already attached to another node",
            ],
        }
