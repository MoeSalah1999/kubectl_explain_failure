from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class VolumeDetachStuckRule(FailureRule):
    """
    Detects storage failures caused by a VolumeAttachment or detach workflow
    that is unable to complete.

    Real-world behavior
    -------------------
    Kubernetes detach operations can become stuck when:

    - CSI external-attacher cannot complete ControllerUnpublishVolume
    - attachdetach-controller cannot reconcile attachment state
    - node disappears while volume remains attached
    - stale VolumeAttachment finalizers block cleanup
    - cloud-provider detach API failures occur
    - storage backend reports volume still in-use
    - force deletion leaves orphaned attachment records
    - CSI controller is unavailable

    Common symptoms:

    - Replacement pod cannot start because volume remains attached
    - Multi-Attach errors appear after workload rescheduling
    - VolumeAttachment objects remain for extended periods
    - PersistentVolume remains attached to a dead node
    - StatefulSet rollout stalls

    This rule focuses specifically on DETACH failures rather than
    ATTACH failures.
    """

    name = "VolumeDetachStuck"
    category = "Storage"
    severity = "High"
    priority = 85
    deterministic = True

    phases = ["Pending", "Running", "Terminating"]

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
        "VolumeAttachmentStuck",
        "FailedMount",
        "MultiAttachError",
    ]

    WINDOW_MINUTES = 120

    DETACH_FAILURE_MARKERS = (
        "detachvolume.detach failed",
        "faileddetachvolume",
        "detach volume",
        "unable to detach volume",
        "volume attachment is being deleted",
        "timed out waiting for the condition",
        "volume is already exclusively attached",
        "could not detach volume",
        "controllerunpublishvolume",
        "failed to unpublish volume",
        "detach operation failed",
        "volume is in use",
        "device busy",
    )

    DETACH_PENDING_MARKERS = (
        "detachvolume",
        "faileddetachvolume",
        "controllerunpublishvolume",
        "volumeattachment",
        "detach volume",
        "unpublish volume",
    )

    ATTACHER_IDENTIFIERS = (
        "external-attacher",
        "csi-attacher",
        "external attacher",
    )

    ATTACHER_FAILURE_MARKERS = (
        "crashloopbackoff",
        "leader election lost",
        "rpc error",
        "deadline exceeded",
        "connection refused",
        "timed out",
        "panic",
        "permission denied",
        "failed to sync",
    )

    WAITING_REASONS = {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerError",
        "CreateContainerConfigError",
        "RunContainerError",
        "ContainerCannotRun",
    }

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

    def _identity_text(
        self,
        obj: dict[str, Any],
    ) -> str:
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

    def _is_attacher_object(
        self,
        obj: dict[str, Any],
    ) -> bool:
        text = self._identity_text(obj)

        return any(ident in text for ident in self.ATTACHER_IDENTIFIERS)

    def _pod_ready(
        self,
        pod_obj: dict[str, Any],
    ) -> bool:
        conditions = pod_obj.get("status", {}).get("conditions", [])

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

            if status.get("phase") not in {
                "Running",
                "Succeeded",
            }:
                degraded.append(pod_obj)
                continue

            if not self._pod_ready(pod_obj):
                degraded.append(pod_obj)
                continue

            for container in (
                status.get(
                    "containerStatuses",
                    [],
                )
                or []
            ):
                state = container.get("state", {}) or {}

                waiting = state.get("waiting", {}) or {}

                terminated = (
                    state.get(
                        "terminated",
                        {},
                    )
                    or {}
                )

                if waiting.get("reason") in self.WAITING_REASONS:
                    degraded.append(pod_obj)
                    break

                if (
                    terminated
                    and int(
                        terminated.get(
                            "exitCode",
                            0,
                        )
                        or 0
                    )
                    != 0
                ):
                    degraded.append(pod_obj)
                    break

        return degraded

    def _volume_attachment_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[
        dict[str, Any] | None,
        str | None,
    ]:
        attachments = context.get("objects", {}).get(
            "volumeattachment",
            {},
        )

        for attachment in attachments.values():
            if not isinstance(
                attachment,
                dict,
            ):
                continue

            metadata = (
                attachment.get(
                    "metadata",
                    {},
                )
                or {}
            )

            deletion_ts = metadata.get("deletionTimestamp")

            finalizers = (
                metadata.get(
                    "finalizers",
                    [],
                )
                or []
            )

            status = (
                attachment.get(
                    "status",
                    {},
                )
                or {}
            )

            attached = status.get("attached")

            detach_error = (
                status.get(
                    "detachError",
                    {},
                )
                or {}
            )

            if detach_error and (
                detach_error.get("message") or detach_error.get("errorCode")
            ):
                message = detach_error.get("message") or detach_error.get("errorCode")

                return (
                    attachment,
                    str(message) if message else ("Volume detach operation failed"),
                )

            if deletion_ts and attached is True:
                return (
                    attachment,
                    (
                        "VolumeAttachment is "
                        "marked for deletion but "
                        "remains attached"
                    ),
                )

            #
            # Only consider finalizers evidence if the object
            # is actually being deleted.
            #
            if deletion_ts and finalizers:
                return (
                    attachment,
                    ("VolumeAttachment deletion " "blocked by finalizers"),
                )

        return None, None

    def _detach_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.DETACH_PENDING_MARKERS):
                matches.append(event)

        return matches

    def _detach_failures(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.DETACH_FAILURE_MARKERS):
                failures.append(event)

        return failures

    def _attacher_failures(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(ident in text for ident in self.ATTACHER_IDENTIFIERS) and any(
                marker in text for marker in self.ATTACHER_FAILURE_MARKERS
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

        detach_failures = self._detach_failures(timeline)

        #
        # VolumeDetachStuck should only fire when we have
        # concrete evidence that a detach workflow is stuck.
        #
        # Event text alone is not sufficient because
        # Multi-Attach and FailedMount scenarios often
        # contain similar wording and are handled by
        # more specific rules.
        #
        if not attachment_signal:
            return None

        degraded_attachers = self._degraded_attacher_pods(context)

        attacher_failures = self._attacher_failures(timeline)

        object_evidence: dict[
            str,
            list[str],
        ] = {}

        signals: list[str] = []

        if attachment_obj and attachment_signal:
            name = self._object_name(attachment_obj)

            object_evidence[f"volumeattachment:{name}"] = [attachment_signal]

            signals.append(attachment_signal)

        for pod_obj in degraded_attachers[:3]:
            pod_name = self._object_name(pod_obj)

            object_evidence[f"pod:{pod_name}"] = [
                "CSI external-attacher pod is degraded"
            ]

            signals.append(
                f"CSI external-attacher pod " f"{pod_name} is not Ready " f"or failing"
            )

        if attacher_failures:
            latest = self._message(attacher_failures[-1])

            object_evidence.setdefault(
                "timeline:csi-attacher",
                [],
            ).append(latest)

            signals.append(f"Recent CSI attacher " f"failure event: {latest}")

        return {
            "detach_failures": detach_failures,
            "signals": list(dict.fromkeys(signals)),
            "object_evidence": (object_evidence),
            "attacher_failures": (attacher_failures),
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
            raise ValueError("VolumeDetachStuck " "requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("VolumeDetachStuck " "explain() called " "without match")

        pod_name = pod.get("metadata", {}).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get("metadata", {}).get(
            "namespace",
            "default",
        )

        failure_count = sum(self._occurrences(e) for e in candidate["detach_failures"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_DETACH_REQUIRED",
                    message=(
                        "The storage system "
                        "must detach a volume "
                        "before attachment can "
                        "be reconciled elsewhere"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="VOLUME_DETACH_STUCK",
                    message=("The CSI detach workflow " "cannot complete"),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ATTACHMENT_STATE_CANNOT_ADVANCE",
                    message=(
                        "Workloads cannot "
                        "progress because "
                        "volume ownership "
                        "remains unresolved"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Pod {namespace}/{pod_name} "
                f"is impacted by a volume "
                f"detach workflow that "
                f"cannot complete"
            ),
            (
                f"Observed {failure_count} "
                f"volume detach failure "
                f"occurrence(s) during "
                f"the incident window"
            ),
        ]

        evidence.extend(candidate["signals"])

        confidence = 0.95

        if candidate["attacher_failures"] and candidate["object_evidence"]:
            confidence = 0.99
        elif candidate["object_evidence"]:
            confidence = 0.97

        return {
            "rule": self.name,
            "root_cause": (
                "Volume detach operation "
                "is stuck and attachment "
                "ownership cannot be "
                "reconciled"
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
                ("VolumeAttachment " "finalizers are blocking " "deletion"),
                ("CSI ControllerUnpublishVolume " "operations are failing"),
                ("Cloud-provider detach " "API failures"),
                ("Node disappeared while " "the volume remained attached"),
                ("Storage backend still " "reports the volume as " "in-use"),
                ("CSI external-attacher " "controller is unhealthy"),
            ],
            "suggested_checks": [
                "kubectl get volumeattachment",
                ("kubectl describe " "volumeattachment " "<attachment>"),
                ("kubectl get events " "--sort-by=.lastTimestamp"),
                ("kubectl get pods -A " "| grep attacher"),
                ("kubectl logs " "<csi-attacher-pod>"),
                ("kubectl get volumeattachment " "-o yaml"),
                (
                    "Verify whether the "
                    "volume is still attached "
                    "at the storage backend"
                ),
                ("Verify ControllerUnpublishVolume " "operations in CSI logs"),
            ],
        }
