from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CSIExternalAttacherUnavailableRule(FailureRule):
    """
    Detects volume attachment failures caused by an unavailable CSI
    external-attacher controller.

    Real-world behavior:
    - The CSI external-attacher sidecar watches VolumeAttachment objects
      and invokes ControllerPublishVolume().
    - If the external-attacher Deployment is unavailable, crashlooping,
      unscheduled, leader-election blocked, RBAC broken, or disconnected
      from the API server, VolumeAttachment objects remain unattached.
    - Pods remain Pending or ContainerCreating while waiting for volume
      attachment.
    - Events frequently contain:
        "timed out waiting for external-attacher"
        "waiting for external-attacher"
        "AttachVolume.Attach failed"
        "external-attacher not found"
        "no CSI attacher"
        "VolumeAttachment not processed"
    - The CSI driver itself may be healthy while only the attacher
      controller is unavailable.

    Exclusions:
    - StorageClass provisioning failures
    - External-provisioner failures
    - Node-stage / node-publish mount failures
    - CSI driver registration failures
    - Cloud-provider volume API failures after attacher successfully runs
    """

    name = "CSIExternalAttacherUnavailable"
    category = "Storage"
    severity = "High"
    priority = 93
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "deployment",
            "pod",
            "volumeattachment",
            "lease",
        ],
    }

    blocks = [
        "FailedAttachVolume",
        "VolumeAttachmentPending",
        "CSIVolumeLimitExceeded",
    ]

    WINDOW_MINUTES = 30

    ATTACHER_IDENTIFIERS = (
        "external-attacher",
        "csi-attacher",
        "csi external-attacher",
    )

    ATTACHER_FAILURE_MARKERS = (
        "timed out waiting for external-attacher",
        "waiting for external-attacher",
        "external-attacher is not running",
        "external-attacher unavailable",
        "external-attacher not found",
        "failed to find external-attacher",
        "no external-attacher",
        "attacher timeout",
        "volumeattachment not processed",
        "volume attachment is being deleted",
        "cannot find attacher",
        "leader election lost",
        "failed to acquire lease",
    )

    ATTACH_REASONS = {
        "FailedAttachVolume",
        "AttachVolume",
        "FailedMount",
        "FailedScheduling",
    }

    ATTACHER_WAITING_REASONS = {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
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

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _is_attacher_failure_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        reason = self._reason(event)
        message = self._message(event).lower()

        if any(marker in message for marker in self.ATTACHER_FAILURE_MARKERS):
            return True

        if reason in self.ATTACH_REASONS:
            return any(
                marker in message
                for marker in (
                    "external-attacher",
                    "csi-attacher",
                    "waiting for external-attacher",
                    "timed out waiting for external-attacher",
                    "external-attacher not found",
                )
            )

        return False

    def _is_attacher_controller_pod(
        self,
        pod_obj: dict[str, Any],
    ) -> bool:
        metadata = pod_obj.get("metadata", {}) or {}

        text = " ".join(
            str(v).lower()
            for v in (
                metadata.get("name"),
                metadata.get("namespace"),
            )
            if v
        )

        labels = metadata.get("labels", {}) or {}
        text += " " + " ".join(f"{k}={v}".lower() for k, v in labels.items())

        spec = pod_obj.get("spec", {}) or {}

        for container in spec.get("containers", []) or []:
            if not isinstance(container, dict):
                continue

            text += " " + str(container.get("name") or "").lower()
            text += " " + str(container.get("image") or "").lower()

        return any(marker in text for marker in self.ATTACHER_IDENTIFIERS)

    def _pod_ready(
        self,
        pod_obj: dict[str, Any],
    ) -> bool:
        if pod_obj.get("status", {}).get("phase") != "Running":
            return False

        for condition in pod_obj.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == "Ready" and condition.get("status") == "True":
                return True

        return False

    def _degraded_attacher_pods(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        degraded = []

        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if not isinstance(pod_obj, dict) or not self._is_attacher_controller_pod(
                pod_obj
            ):
                continue

            if not self._pod_ready(pod_obj):
                degraded.append(pod_obj)
                continue

            for container in (
                pod_obj.get("status", {}).get("containerStatuses", []) or []
            ):
                state = container.get("state", {}) or {}
                waiting = state.get("waiting", {}) or {}

                if waiting.get("reason") in self.ATTACHER_WAITING_REASONS:
                    degraded.append(pod_obj)
                    break

                last_state = container.get("lastState", {}).get("terminated", {}) or {}

                if (
                    last_state
                    and int(last_state.get("exitCode", 0) or 0) != 0
                    and int(container.get("restartCount", 0) or 0) > 0
                ):
                    degraded.append(pod_obj)
                    break

        return degraded

    def _volume_attachment_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[str | None, dict[str, list[str]]]:
        object_evidence: dict[str, list[str]] = {}

        for name, attachment in (
            context.get("objects", {}).get("volumeattachment", {}).items()
        ):
            if not isinstance(attachment, dict):
                continue

            status = attachment.get("status", {}) or {}

            attached = status.get("attached")
            attach_error = status.get("attachError", {}).get("message", "").lower()

            if attached is False and any(
                marker in attach_error
                for marker in (
                    "external-attacher",
                    "waiting for external-attacher",
                    "attacher",
                )
            ):
                error = status.get("attachError", {}).get("message")

                signal = f"VolumeAttachment {name} remains unattached"

                if error:
                    signal += f": {error}"

                object_evidence[f"volumeattachment:{name}"] = [signal]

                return signal, object_evidence

        return None, object_evidence

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        recent_events = self._recent_events(timeline)

        attacher_events = [
            e for e in recent_events if self._is_attacher_failure_event(e)
        ]

        degraded_pods = self._degraded_attacher_pods(context)

        volume_signal, object_evidence = self._volume_attachment_signal(context)

        #
        # Deterministic attacher outages require BOTH:
        #
        # 1. Explicit workload-facing evidence that attachment is blocked
        #    because of the external-attacher.
        #
        # 2. Infrastructure evidence that the attacher controller itself
        #    is unhealthy or unable to process VolumeAttachment objects.
        #
        # We intentionally do NOT fire solely because:
        #   - a CSI controller pod is unhealthy
        #   - a VolumeAttachment is unattached
        #
        # Otherwise this rule hijacks unrelated storage, scheduling,
        # configuration, and infrastructure failures.
        #
        has_workload_attacher_failure = bool(attacher_events)

        has_attacher_infrastructure_evidence = bool(degraded_pods) or bool(
            volume_signal
        )

        if not has_workload_attacher_failure:
            return None

        if not has_attacher_infrastructure_evidence:
            return None

        occurrences = sum(self._occurrences(e) for e in attacher_events)

        duration = timeline.duration_between(self._is_attacher_failure_event)

        degraded_signals: list[str] = []

        for pod_obj in degraded_pods[:3]:
            name = pod_obj.get("metadata", {}).get("name", "<unknown>")

            degraded_signals.append(f"CSI external-attacher pod {name} is not healthy")

            object_evidence[f"pod:{name}"] = [
                "CSI external-attacher controller is unavailable"
            ]

        if volume_signal:
            degraded_signals.append(volume_signal)

        return {
            "events": attacher_events,
            "occurrences": occurrences,
            "duration": duration,
            "degraded_signals": degraded_signals,
            "object_evidence": object_evidence,
            "representative_event": (
                self._message(attacher_events[-1]) if attacher_events else volume_signal
            ),
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("CSIExternalAttacherUnavailable requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "CSIExternalAttacherUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_EXTERNAL_ATTACHER_REQUIRED",
                    message=(
                        "The CSI external-attacher controller is "
                        "required to process VolumeAttachment objects"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="CSI_EXTERNAL_ATTACHER_UNAVAILABLE",
                    message=(
                        "The CSI external-attacher controller is "
                        "unavailable or unhealthy"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_ATTACHMENTS_NOT_PROCESSED",
                    message=(
                        "VolumeAttachment objects cannot be processed " "or completed"
                    ),
                    role="controller_failure",
                ),
                Cause(
                    code="POD_STORAGE_ATTACH_BLOCKED",
                    message=("The pod cannot attach required persistent volumes"),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Pod {namespace}/{pod_name} is blocked waiting "
                "for CSI volume attachment"
            ),
            (
                f"Representative attacher failure signal: "
                f"{candidate['representative_event']}"
            ),
        ]

        if candidate["occurrences"]:
            evidence.append(
                f"Observed {candidate['occurrences']} CSI external-attacher "
                f"failure occurrence(s) within the last "
                f"{self.WINDOW_MINUTES} minutes"
            )

        if candidate["duration"]:
            evidence.append(
                f"Attacher-related failures persisted for "
                f"{candidate['duration'] / 60:.1f} minutes"
            )

        evidence.extend(candidate["degraded_signals"])

        confidence = 0.92

        if candidate["events"] and candidate["object_evidence"]:
            confidence = 0.98
        elif candidate["object_evidence"]:
            confidence = 0.96

        object_evidence = {
            f"pod:{pod_name}": [candidate["representative_event"]],
            **candidate["object_evidence"],
        }

        return {
            "rule": self.name,
            "root_cause": ("CSI external-attacher controller is unavailable"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "The CSI external-attacher Deployment is crashlooping or not Ready",
                "Leader election failure prevents the active attacher from processing VolumeAttachment objects",
                "RBAC permissions prevent the attacher from watching or updating VolumeAttachment resources",
                "The external-attacher cannot communicate with the Kubernetes API server",
                "The CSI controller pod hosting the external-attacher sidecar is unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get volumeattachments",
                "kubectl describe volumeattachments",
                "kubectl get pods -A | grep attacher",
                "kubectl logs <csi-controller-pod> -c csi-attacher",
                "kubectl describe deployment <csi-controller-deployment>",
                "kubectl get lease -A",
                "Verify leader election, RBAC permissions, and CSI controller health",
            ],
        }
