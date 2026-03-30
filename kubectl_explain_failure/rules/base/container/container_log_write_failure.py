from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class ContainerLogWriteFailureRule(FailureRule):
    """
    Detects container startup failures caused by the runtime or node OS being
    unable to create or write the container's log path.

    Real-world behavior:
    - kubelet and container runtimes often surface this as failures creating
      log symlinks or writing under `/var/log/pods` or `/var/log/containers`
    - common node-side errors include `no space left on device`,
      `disk quota exceeded`, or low-level I/O failures on the log path
    - the container usually remains in CreateContainerError, RunContainerError,
      or ContainerCreating because startup cannot complete once log setup fails
    """

    name = "ContainerLogWriteFailure"
    category = "Container"
    priority = 88
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ContainerRuntimeStartFailure",
    ]

    FAILURE_MARKERS = (
        "no space left on device",
        "disk quota exceeded",
        "input/output error",
        "i/o error",
        "file too large",
    )

    LOG_CONTEXT_MARKERS = (
        "/var/log/pods",
        "/var/log/containers",
        "container log",
        "log file",
        "log symlink",
        "create symbolic link",
        "failed to create symbolic link",
        "failed to create container log",
        "failed to open log file",
        "failed to write log",
        "logger",
        ".log",
    )

    STARTUP_CONTEXT_MARKERS = (
        "failed to start container",
        "failed to create containerd task",
        "failed to create shim task",
        "container runtime",
        "createcontainer",
        "starting container",
    )

    EXCLUSION_MARKERS = (
        "overlay",
        "overlayfs",
        "snapshot",
        "snapshotter",
        "rootfs",
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

    def _is_log_write_failure_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        if not any(marker in msg for marker in self.FAILURE_MARKERS):
            return False

        has_log_context = any(marker in msg for marker in self.LOG_CONTEXT_MARKERS)
        has_startup_context = any(
            marker in msg for marker in self.STARTUP_CONTEXT_MARKERS
        )

        return (
            has_log_context
            or has_startup_context
            and ("/var/log/" in msg or "log" in msg)
        )

    def _matching_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if self._is_log_write_failure_message(str(event.get("message", "")))
        ]

    def _matching_waiting_messages(self, pod: dict) -> list[str]:
        messages = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") not in self.WAITING_REASONS:
                continue

            message = waiting.get("message") or ""
            if self._is_log_write_failure_message(message):
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
                    code="CONTAINER_LOG_PATH_SETUP_STARTED",
                    message="Kubelet asked the runtime to initialize the container log path before startup",
                    role="execution_context",
                ),
                Cause(
                    code="CONTAINER_LOG_WRITE_FAILED",
                    message="The node or runtime could not create or write the container log path",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_STARTUP_ABORTED",
                    message="Container cannot finish startup because log initialization failed on the node",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container log path could not be created or written by the runtime",
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Kubelet or runtime reports failure while creating or writing the container log path",
                "Container remains in a waiting startup error state instead of reaching a started state",
                *(
                    [f"Log path failure repeated {total_failures} times"]
                    if total_failures > 1
                    else []
                ),
                *(["Dominant log path error: " + dominant_msg] if dominant_msg else []),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because the runtime could not create or write its container logs"
                ]
            },
            "likely_causes": [
                "The node filesystem backing /var/log/pods or /var/log/containers is full or quota-limited",
                "Node log storage experienced I/O failures while kubelet or the runtime created container log files",
                "Container log rotation or cleanup did not reclaim enough space on the node log path",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect kubelet and containerd or CRI-O logs for log file or symlink creation failures",
                "Check node disk usage and health for /var/log/pods and /var/log/containers",
                "Review container log rotation and cleanup configuration on the node",
            ],
        }
