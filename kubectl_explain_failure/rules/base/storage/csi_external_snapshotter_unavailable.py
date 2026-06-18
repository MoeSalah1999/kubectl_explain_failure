from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CSIExternalSnapshotterUnavailableRule(FailureRule):
    """
    Detects VolumeSnapshot / VolumeSnapshotContent failures caused by an
    unavailable CSI external-snapshotter controller.

    Real-world behavior:
    - CSI snapshots require the external-snapshotter sidecar/controller.
    - When the snapshotter is unavailable, VolumeSnapshots remain stuck
      waiting for reconciliation and ReadyToUse never becomes True.
    - Snapshot controller pods may be CrashLooping, unavailable,
      unscheduled, partially rolled out, or leader-election broken.
    - Events commonly contain:
          waiting for snapshot controller
          failed to create snapshot
          snapshot operation failed
          failed to sync volumesnapshot
          failed to update volumesnapshotcontent
          deadline exceeded
          rpc error

    Exclusions:
    - Backend storage snapshot capability not supported
    - SnapshotClass misconfiguration
    - Invalid VolumeSnapshot references
    - Snapshot deletion finalizer issues unrelated to controller health
    - CSI driver-specific snapshot errors when controller is healthy
    """

    name = "CSIExternalSnapshotterUnavailable"
    category = "Storage"
    severity = "High"
    priority = 79
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "deployment",
            "statefulset",
            "volumesnapshot",
            "volumesnapshotcontent",
            "volumesnapshotclass",
        ],
    }

    blocks = [
        "VolumeSnapshotPending",
        "VolumeSnapshotFailed",
    ]

    WINDOW_MINUTES = 60

    SNAPSHOTTER_IDENTIFIERS = (
        "external-snapshotter",
        "csi-snapshotter",
        "snapshot-controller",
        "snapshot controller",
        "external snapshotter",
    )

    SNAPSHOT_PENDING_MARKERS = (
        "volumesnapshot",
        "volumesnapshotcontent",
        "snapshot",
        "waiting for snapshot",
        "waiting for snapshot controller",
        "snapshot operation",
        "create snapshot",
        "snapshot creation",
        "readytouse",
    )

    SNAPSHOTTER_FAILURE_MARKERS = (
        "crashloopbackoff",
        "back-off restarting failed container",
        "failed to sync",
        "failed to reconcile",
        "leader election lost",
        "leader election",
        "rpc error",
        "deadline exceeded",
        "connection refused",
        "timed out",
        "panic",
        "unable to create snapshot",
        "failed to create snapshot",
        "failed to update volumesnapshot",
        "failed to update volumesnapshotcontent",
        "error syncing",
        "permission denied",
    )

    SNAPSHOTTER_WAITING_REASONS = {
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

    def _is_snapshotter_object(self, obj: dict[str, Any]) -> bool:
        text = self._identity_text(obj)
        return any(marker in text for marker in self.SNAPSHOTTER_IDENTIFIERS)

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        conditions = pod_obj.get("status", {}).get("conditions", []) or []

        return any(
            c.get("type") == "Ready" and c.get("status") == "True" for c in conditions
        )

    def _degraded_snapshotter_pods(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        degraded = []

        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if not isinstance(pod_obj, dict):
                continue

            if not self._is_snapshotter_object(pod_obj):
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

                if waiting.get("reason") in self.SNAPSHOTTER_WAITING_REASONS:
                    degraded.append(pod_obj)
                    break

                if terminated and int(terminated.get("exitCode", 0) or 0) != 0:
                    degraded.append(pod_obj)
                    break

        return degraded

    def _deployment_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        for deployment in (
            context.get("objects", {})
            .get(
                "deployment",
                {},
            )
            .values()
        ):
            if not isinstance(deployment, dict):
                continue

            if not self._is_snapshotter_object(deployment):
                continue

            status = deployment.get("status", {}) or {}

            replicas = int(status.get("replicas", 0) or 0)
            ready = int(status.get("readyReplicas", 0) or 0)
            available = int(status.get("availableReplicas", 0) or 0)

            if replicas > 0 and (ready < replicas or available < replicas):
                return (
                    deployment,
                    (
                        "CSI external-snapshotter deployment unavailable "
                        f"(ready={ready}, available={available}, replicas={replicas})"
                    ),
                )

        return None, None

    def _snapshot_object_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        snapshots = context.get(
            "objects",
            {},
        ).get(
            "volumesnapshot",
            {},
        )

        for snapshot in snapshots.values():
            if not isinstance(snapshot, dict):
                continue

            status = snapshot.get("status", {}) or {}

            ready = status.get("readyToUse")

            if ready is False:
                error = status.get("error", {}) or {}
                message = str(error.get("message") or "")

                return (
                    snapshot,
                    (message or "VolumeSnapshot exists but ReadyToUse=False"),
                )

        return None, None

    def _snapshot_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.SNAPSHOT_PENDING_MARKERS):
                matches.append(event)

        return matches

    def _snapshotter_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(ident in text for ident in self.SNAPSHOTTER_IDENTIFIERS) and any(
                marker in text for marker in self.SNAPSHOTTER_FAILURE_MARKERS
            ):
                failures.append(event)

        return failures

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        snapshot_events = self._snapshot_events(timeline)

        snapshot_obj, snapshot_signal = self._snapshot_object_signal(context)

        if not snapshot_events and not snapshot_signal:
            return None

        degraded_pods = self._degraded_snapshotter_pods(context)

        deployment, deployment_signal = self._deployment_signal(context)

        failure_events = self._snapshotter_failure_events(timeline)

        if not degraded_pods and not deployment_signal and not failure_events:
            return None

        object_evidence: dict[str, list[str]] = {}
        signals: list[str] = []

        if snapshot_obj and snapshot_signal:
            name = self._object_name(snapshot_obj)

            object_evidence[f"volumesnapshot:{name}"] = [snapshot_signal]

            signals.append(snapshot_signal)

        for pod_obj in degraded_pods[:3]:
            pod_name = self._object_name(pod_obj)

            object_evidence[f"pod:{pod_name}"] = [
                "CSI external-snapshotter pod is degraded"
            ]

            signals.append(
                f"CSI external-snapshotter pod {pod_name} is not Ready or failing"
            )

        if deployment_signal:
            deploy_name = self._object_name(deployment or {})

            if deploy_name:
                object_evidence[f"deployment:{deploy_name}"] = [deployment_signal]

            signals.append(deployment_signal)

        if failure_events:
            latest = self._message(failure_events[-1])

            object_evidence.setdefault(
                "timeline:external-snapshotter",
                [],
            ).append(latest)

            signals.append(f"Recent external-snapshotter failure event: {latest}")

        return {
            "snapshot_events": snapshot_events,
            "failure_events": failure_events,
            "signals": list(dict.fromkeys(signals)),
            "object_evidence": object_evidence,
        }

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
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
            raise ValueError(
                "CSIExternalSnapshotterUnavailable requires Timeline context"
            )

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "CSIExternalSnapshotterUnavailable explain() called without match"
            )

        pod_name = pod.get(
            "metadata",
            {},
        ).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get(
            "metadata",
            {},
        ).get(
            "namespace",
            "default",
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SNAPSHOT_OPERATION_REQUESTED",
                    message="A VolumeSnapshot operation is pending",
                    role="runtime_context",
                ),
                Cause(
                    code="CSI_EXTERNAL_SNAPSHOTTER_UNAVAILABLE",
                    message="CSI external-snapshotter controller is unavailable or unhealthy",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SNAPSHOT_RECONCILIATION_CANNOT_PROGRESS",
                    message="VolumeSnapshot reconciliation cannot proceed without a functioning snapshot controller",
                    role="workload_symptom",
                ),
            ]
        )

        snapshot_occurrences = sum(
            self._occurrences(e) for e in candidate["snapshot_events"]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} depends on snapshot operations that are not progressing",
            (
                f"Observed {snapshot_occurrences} snapshot-related "
                "event occurrence(s) in the recent incident window"
            ),
        ]

        evidence.extend(candidate["signals"])

        confidence = 0.92

        if candidate["failure_events"] and candidate["object_evidence"]:
            confidence = 0.98
        elif candidate["object_evidence"]:
            confidence = 0.96

        return {
            "rule": self.name,
            "root_cause": ("CSI external-snapshotter controller is unavailable"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v))
                for k, v in candidate["object_evidence"].items()
            },
            "likely_causes": [
                "The CSI external-snapshotter pod is CrashLooping or not Ready",
                "The snapshot-controller deployment is unavailable or partially rolled out",
                "Leader-election failures prevent snapshot reconciliation",
                "RBAC or API permission issues prevent VolumeSnapshot updates",
                "The CSI driver upgrade left the snapshotter sidecar unavailable",
            ],
            "suggested_checks": [
                "kubectl get volumesnapshot -A",
                "kubectl describe volumesnapshot <snapshot-name>",
                "kubectl get volumesnapshotcontent",
                "kubectl get pods -A | grep snapshot",
                "kubectl logs <snapshot-controller-pod>",
                "kubectl describe deployment snapshot-controller",
                "kubectl get events --sort-by=.lastTimestamp",
            ],
        }
