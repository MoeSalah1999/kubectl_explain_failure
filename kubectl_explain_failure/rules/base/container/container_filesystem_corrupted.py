from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class ContainerFilesystemCorruptedRule(FailureRule):
    """
    Detects container startup failures caused by corruption in the runtime's
    container filesystem or snapshot storage on the node.

    Real-world behavior:
    - kubelet/containerd often surfaces this as rootfs/overlay/snapshot errors
      such as `structure needs cleaning`, `input/output error`, or explicit
      `corrupt/corrupted` markers
    - the container usually never reaches a stable started state and remains in
      CreateContainerError or RunContainerError while kubelet retries
    - this is narrower than a generic runtime start failure and should win when
      the message explicitly implicates runtime filesystem corruption
    """

    name = "ContainerFilesystemCorrupted"
    category = "Container"
    priority = 88
    deterministic = True

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ContainerRuntimeStartFailure",
    ]

    STRONG_CORRUPTION_MARKERS = (
        "structure needs cleaning",
        "filesystem corruption",
        "filesystem is corrupted",
        "corrupt",
        "corrupted",
        "metadata checksum error",
    )

    IO_CORRUPTION_MARKERS = (
        "input/output error",
        "i/o error",
        "transport endpoint is not connected",
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
        "error creating overlay mount",
        "failed to prepare rootfs",
        "failed to extract layer",
        "error mounting",
        "apply layer",
        "unpack image",
    )

    EXCLUSION_MARKERS = (
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
        "ContainerCannotRun",
    }

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_filesystem_corruption_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        has_fs_context = any(
            marker in msg for marker in self.FILESYSTEM_CONTEXT_MARKERS
        )
        has_runtime_context = any(
            marker in msg for marker in self.RUNTIME_CONTEXT_MARKERS
        )

        if not (has_fs_context or has_runtime_context):
            return False

        if any(marker in msg for marker in self.STRONG_CORRUPTION_MARKERS):
            return True

        return (
            has_fs_context
            and has_runtime_context
            and any(marker in msg for marker in self.IO_CORRUPTION_MARKERS)
        )

    def _matching_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if self._is_filesystem_corruption_message(str(event.get("message", "")))
        ]

    def _matching_waiting_messages(self, pod: dict) -> list[str]:
        messages = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") not in self.WAITING_REASONS:
                continue

            message = waiting.get("message") or ""
            if self._is_filesystem_corruption_message(message):
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
                    code="CONTAINER_ROOTFS_PREPARATION_STARTED",
                    message="Kubelet asked the runtime to prepare the container root filesystem",
                    role="execution_context",
                ),
                Cause(
                    code="CONTAINER_FILESYSTEM_CORRUPTED",
                    message="Container runtime storage or root filesystem on the node is corrupted",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_CANNOT_BE_CREATED",
                    message="Container cannot start because the runtime cannot mount or unpack its filesystem",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container runtime storage is corrupted and prevents container startup",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Kubelet or runtime reports overlay/rootfs/layer corruption while preparing the container filesystem",
                "Container remains in a waiting startup error state instead of reaching a started state",
                *(
                    [
                        f"Corruption-shaped runtime failure repeated {total_failures} times"
                    ]
                    if total_failures > 1
                    else []
                ),
                *(
                    ["Dominant corruption error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because the runtime filesystem backing the container is corrupted"
                ]
            },
            "likely_causes": [
                "overlayfs or snapshotter data under the container runtime storage path is corrupted",
                "Underlying node disk or filesystem errors damaged container runtime metadata or layers",
                "A node crash or unclean shutdown left containerd or Docker layer state inconsistent",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect kubelet and containerd or CRI-O logs for overlayfs, snapshot, or rootfs corruption messages",
                "Check node dmesg and filesystem health for disk or metadata corruption",
                "Inspect the runtime storage path under /var/lib/containerd or /var/lib/docker on the node",
            ],
        }
