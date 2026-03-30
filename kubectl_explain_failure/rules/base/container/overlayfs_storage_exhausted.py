from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class OverlayFSStorageExhaustedRule(FailureRule):
    """
    Detects container startup failures caused by exhausted runtime storage in
    overlayfs or a snapshot-backed rootfs path on the node.

    Real-world behavior:
    - kubelet/containerd often emits `no space left on device` while creating
      overlay mounts, unpacking image layers, or preparing the container rootfs
    - the container typically remains in CreateContainerError or RunContainerError
      because the runtime cannot materialize the writable layer
    - this is narrower than generic runtime start failure and more directly
      actionable than a broad node DiskPressure diagnosis when the pod-level
      runtime message explicitly identifies overlay/snapshot storage exhaustion
    """

    name = "OverlayFSStorageExhausted"
    category = "Container"
    priority = 89
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ContainerRuntimeStartFailure",
        "NodeDiskPressure",
    ]

    NO_SPACE_MARKERS = (
        "no space left on device",
        "disk quota exceeded",
    )

    FILESYSTEM_CONTEXT_MARKERS = (
        "overlay",
        "overlayfs",
        "snapshot",
        "snapshotter",
        "rootfs",
        "layer",
        "diff",
        "merged",
        "/var/lib/containerd",
        "/var/lib/docker",
    )

    RUNTIME_CONTEXT_MARKERS = (
        "failed to create containerd task",
        "failed to start container",
        "failed to prepare rootfs",
        "failed to extract layer",
        "error creating overlay mount",
        "error mounting",
        "apply layer",
        "unpack image",
        "write layer",
    )

    EXCLUSION_MARKERS = (
        "structure needs cleaning",
        "filesystem corruption",
        "corrupt",
        "corrupted",
        "read-only file system",
        "permission denied",
        "context deadline exceeded",
        "deadline exceeded",
        "timed out",
        "not found",
        "no such file or directory",
        "exec format error",
        "seccomp",
        "apparmor",
    )

    WAITING_REASONS = {
        "CreateContainerError",
        "RunContainerError",
        "ContainerCreating",
    }

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_overlayfs_storage_exhaustion_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        if not any(marker in msg for marker in self.NO_SPACE_MARKERS):
            return False

        has_fs_context = any(
            marker in msg for marker in self.FILESYSTEM_CONTEXT_MARKERS
        )
        has_runtime_context = any(
            marker in msg for marker in self.RUNTIME_CONTEXT_MARKERS
        )
        return has_fs_context or has_runtime_context

    def _matching_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if self._is_overlayfs_storage_exhaustion_message(
                str(event.get("message", ""))
            )
        ]

    def _matching_waiting_messages(self, pod: dict) -> list[str]:
        messages = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") not in self.WAITING_REASONS:
                continue

            message = waiting.get("message") or ""
            if self._is_overlayfs_storage_exhaustion_message(message):
                messages.append(message)
        return messages

    def _has_waiting_start_error(self, pod: dict) -> bool:
        return any(
            (status.get("state", {}).get("waiting") or {}).get("reason")
            in self.WAITING_REASONS
            for status in pod.get("status", {}).get("containerStatuses", []) or []
        )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not timeline_has_event(
            timeline,
            kind="Generic",
            phase="Failure",
            source="kubelet",
        ):
            return False

        matched_events = self._matching_events(timeline)
        waiting_messages = self._matching_waiting_messages(pod)

        if not matched_events and not waiting_messages:
            return False

        if waiting_messages:
            return True

        return bool(matched_events) and self._has_waiting_start_error(pod)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []
        waiting_messages = self._matching_waiting_messages(pod)

        total_failures = sum(self._occurrences(event) for event in matched_events)
        messages = [
            str(event.get("message", ""))
            for event in matched_events
            for _ in range(self._occurrences(event))
        ]
        messages.extend(waiting_messages)
        dominant_msg = max(set(messages), key=messages.count) if messages else None

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_LAYER_PREPARATION_STARTED",
                    message="Kubelet asked the runtime to prepare the container writable layer and root filesystem",
                    role="execution_context",
                ),
                Cause(
                    code="OVERLAYFS_STORAGE_EXHAUSTED",
                    message="Overlay or snapshot-backed runtime storage on the node ran out of space",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_CANNOT_START",
                    message="Container cannot start because the runtime cannot allocate or mount its writable filesystem layer",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Overlay or snapshot-backed runtime storage is exhausted and blocks container startup",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Kubelet or runtime reports overlay or snapshot-backed container storage ran out of space",
                "Container remains in a waiting startup error state instead of reaching a started state",
                *(
                    [
                        f"Storage exhaustion-shaped runtime failure repeated {total_failures} times"
                    ]
                    if total_failures > 1
                    else []
                ),
                *(
                    ["Dominant storage exhaustion error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because overlay or snapshot-backed runtime storage is out of space"
                ]
            },
            "likely_causes": [
                "Container runtime storage under /var/lib/containerd or /var/lib/docker is full",
                "Image layers, snapshots, or writable container layers consumed the remaining node filesystem space",
                "Node cleanup or image garbage collection did not reclaim enough runtime storage",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect kubelet and containerd or CRI-O logs for overlayfs, snapshot, or rootfs no-space errors",
                "Check node disk usage for the runtime storage path and image layer directories",
                "Review image garbage collection and log cleanup on the affected node",
            ],
        }
