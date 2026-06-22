from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ImageFilesystemFullRule(FailureRule):
    """
    Detects pod startup and runtime failures caused by exhaustion of the
    node image filesystem (imagefs).

    Real-world behavior:
    - kubelet monitors imagefs.available and imagefs.inodesFree
    - image pulls fail when imagefs becomes full
    - image garbage collection may fail to reclaim enough space
    - kubelet may report DiskPressure
    - pods may be evicted due to ephemeral-storage pressure
    - containerd / CRI-O / Docker may fail image unpack, extraction,
      snapshot creation, or layer writes

    Exclusions:
    - registry authentication failures
    - image not found
    - DNS failures
    - network failures reaching registries
    - CPU or memory pressure unrelated to storage
    """

    name = "ImageFilesystemFull"
    category = "Node"
    severity = "High"
    priority = 88
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "node",
        ],
    }

    WINDOW_MINUTES = 30

    IMAGEFS_MARKERS = (
        "imagefs",
        "image filesystem",
        "image filesystem is full",
        "imagefs.available",
        "imagefs.inodesfree",
        "diskpressure",
        "disk pressure",
        "node has disk pressure",
        "eviction manager",
        "eviction threshold",
        "ephemeral-storage",
        "ephemeral storage",
    )

    IMAGE_PULL_FAILURE_MARKERS = (
        "failed to unpack image",
        "failed to extract layer",
        "failed to register layer",
        "failed to create image filesystem",
        "image garbage collection failed",
        "garbage collection failed",
        "failed to garbage collect",
        "imagefs.available",
        "imagefs.inodesfree",
        "image filesystem is full",
    )

    EVICTION_MARKERS = (
        "evicted",
        "the node was low on resource",
        "ephemeral-storage",
        "ephemeral storage",
        "disk pressure",
    )

    EXCLUSIONS = (
        "not found",
        "manifest unknown",
        "unauthorized",
        "authentication required",
        "pull access denied",
        "tls handshake timeout",
        "i/o timeout",
        "context deadline exceeded",
        "connection refused",
        "no such host",
    )

    FILESYSTEM_CORRUPTION_EXCLUSIONS = (
        "read-only file system",
        "structure needs cleaning",
        "input/output error",
        "i/o error",
        "filesystem corruption",
        "corrupt filesystem",
        "corrupted filesystem",
        "overlayfs:",
    )

    NODE_PRESSURE_CONDITIONS = {
        "DiskPressure",
    }

    RECOVERY_REASONS = {
        "NodeHasNoDiskPressure",
        "FreeDiskSpaceSucceeded",
        "ImageGCSucceeded",
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

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        indexed = list(enumerate(recent))

        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _targets_current_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})

        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind") or "").lower()

        if kind and kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")

        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False

        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False

        return True

    def _is_imagefs_failure_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        if any(marker in text for marker in self.EXCLUSIONS):
            return False

        if any(marker in text for marker in self.FILESYSTEM_CORRUPTION_EXCLUSIONS):
            return False

        strong_imagefs_markers = (
            "imagefs.available",
            "imagefs.inodesfree",
            "image filesystem",
            "image garbage collection failed",
            "failed to garbage collect",
            "failed to create image filesystem",
            "diskpressure",
            "node has disk pressure",
            "eviction manager",
            "eviction threshold",
        )

        return any(marker in text for marker in strong_imagefs_markers)

    def _is_pod_storage_symptom(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False

        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        if any(marker in text for marker in self.EXCLUSIONS):
            return False

        if any(marker in text for marker in self.FILESYSTEM_CORRUPTION_EXCLUSIONS):
            return False

        return any(
            marker in text
            for marker in (
                "failed to unpack image",
                "failed to extract layer",
                "failed to register layer",
                "failed to create image filesystem",
                "image garbage collection failed",
                "evicted",
            )
        )

    def _node_disk_pressure(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> str | None:
        if not node_name:
            return None

        node = context.get("objects", {}).get("node", {}).get(node_name)

        if not isinstance(node, dict):
            return None

        for condition in node.get("status", {}).get("conditions", []) or []:
            if (
                condition.get("type") in self.NODE_PRESSURE_CONDITIONS
                and condition.get("status") == "True"
            ):
                return f"Node {node_name} reports " f"{condition.get('type')}=True"

        return None

    def _recovered_after(
        self,
        timeline: Timeline,
        failure_time: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if self._reason(event) not in self.RECOVERY_REASONS:
                continue

            event_time = self._event_time(event)

            if failure_time is None or event_time is None or event_time >= failure_time:
                return True

        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        node_name = pod.get("spec", {}).get("nodeName")

        recent_events = self._ordered_recent_events(timeline)

        pod_events = [
            event for event in recent_events if self._is_pod_storage_symptom(event, pod)
        ]

        imagefs_events = [
            event for event in recent_events if self._is_imagefs_failure_event(event)
        ]

        imagefs_event_text = " ".join(
            (f"{self._reason(event)} " f"{self._message(event)}").lower()
            for event in imagefs_events
        )

        if "failed to pull image" in imagefs_event_text and not any(
            marker in imagefs_event_text
            for marker in (
                "imagefs",
                "diskpressure",
                "image garbage collection",
                "image filesystem",
            )
        ):
            return None

        node_signal = self._node_disk_pressure(
            context,
            node_name,
        )

        strong_imagefs_signal = bool(imagefs_events) or bool(node_signal)

        if not strong_imagefs_signal:
            return None

        if not pod_events and not node_signal:
            return None

        latest_failure = (
            self._event_time(imagefs_events[-1]) if imagefs_events else None
        )

        if self._recovered_after(
            timeline,
            latest_failure,
        ):
            return None

        duration_seconds = timeline.duration_between(
            lambda event: (
                self._is_imagefs_failure_event(event)
                or self._is_pod_storage_symptom(event, pod)
            )
        )

        evidence = []

        if imagefs_events:
            evidence.append(self._message(imagefs_events[-1]))

        if node_signal:
            evidence.append(node_signal)

        return {
            "node_name": node_name,
            "pod_events": pod_events,
            "imagefs_events": imagefs_events,
            "duration_seconds": duration_seconds,
            "evidence": evidence,
            "representative_message": (
                self._message(imagefs_events[-1] if imagefs_events else pod_events[-1])
            ),
            "pod_occurrences": sum(self._occurrences(event) for event in pod_events),
            "imagefs_occurrences": sum(
                self._occurrences(event) for event in imagefs_events
            ),
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("ImageFilesystemFull requires Timeline context")

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("ImageFilesystemFull explain() called without match")

        pod_name = pod.get("metadata", {}).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get("metadata", {}).get(
            "namespace",
            "default",
        )

        node_name = candidate["node_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_IMAGE_FILESYSTEM_EXHAUSTED",
                    message=(
                        "The node image filesystem "
                        "does not have sufficient free space"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_OR_STORAGE_OPERATIONS_FAIL",
                    message=(
                        "Container runtime cannot reliably "
                        "pull, unpack, store, or manage images"
                    ),
                    role="runtime_failure",
                ),
                Cause(
                    code="POD_STARTUP_OR_RUNTIME_FAILURE",
                    message=(
                        "The workload cannot start or "
                        "is evicted because storage operations fail"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} shows image-storage related failures",
            f"Representative failure: {candidate['representative_message']}",
            (
                f"Observed {candidate['pod_occurrences']} workload "
                f"storage-related occurrence(s)"
            ),
        ]

        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")

        evidence.extend(candidate["evidence"])

        if candidate["imagefs_occurrences"]:
            evidence.append(
                f"Observed {candidate['imagefs_occurrences']} "
                f"image filesystem failure occurrence(s)"
            )

        if candidate["duration_seconds"]:
            evidence.append(
                f"Storage pressure persisted for "
                f"{candidate['duration_seconds'] / 60:.1f} minutes"
            )

        object_evidence = {f"pod:{pod_name}": [candidate["representative_message"]]}

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Node image filesystem exhaustion impacts workload startup/runtime"
            ]

        confidence = 0.97 if candidate["imagefs_events"] else 0.92

        return {
            "rule": self.name,
            "root_cause": "Node image filesystem is full",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": object_evidence,
            "likely_causes": [
                "Image filesystem capacity has been exhausted",
                "Image garbage collection cannot reclaim enough space",
                "Large image pulls consumed remaining imagefs storage",
                "Container runtime snapshot/layer storage is full",
                "Node entered DiskPressure due to image storage exhaustion",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                *([f"kubectl describe node {node_name}"] if node_name else []),
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe node <node>",
                "kubectl top node",
                "crictl images",
                "crictl imagefsinfo",
                "df -h",
                "du -sh /var/lib/containerd/*",
                "journalctl -u kubelet",
            ],
        }
