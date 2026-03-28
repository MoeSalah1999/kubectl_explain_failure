from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class EntrypointPermissionDeniedRule(FailureRule):
    """
    Detects containers whose configured entrypoint exists but cannot be executed
    because of filesystem execute-bit or ownership/permission problems.

    Real-world behavior:
    - kubelet/runtime errors usually include `exec: ... permission denied`,
      `fork/exec ... permission denied`, or `starting container process caused`
    - the container commonly stays in RunContainerError or CreateContainerError
    - this is more specific than generic invalid entrypoint and generic runtime
      permission denial, so it should win when the message explicitly points at
      executing the entrypoint/script/binary
    """

    name = "EntrypointPermissionDenied"
    category = "Container"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "InvalidEntrypoint",
        "ContainerRuntimePermissionDenied",
        "CrashLoopBackOff",
    ]

    WAITING_REASONS = {
        "RunContainerError",
        "CreateContainerError",
    }

    PERMISSION_MARKER = "permission denied"
    EXECUTION_MARKERS = (
        "exec:",
        "fork/exec",
        "starting container process caused",
        "entrypoint",
    )
    EXCLUSION_MARKERS = (
        "seccomp",
        "apparmor",
        "operation not permitted",
        "exec format error",
        "executable file not found",
        "no such file or directory",
        "not found",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_entrypoint_permission_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if self.PERMISSION_MARKER not in msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        return any(marker in msg for marker in self.EXECUTION_MARKERS)

    def _matching_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            message = str(event.get("message", ""))
            if self._is_entrypoint_permission_message(message):
                matches.append(event)
        return matches

    def _matching_waiting_messages(self, pod: dict) -> list[str]:
        messages = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") not in self.WAITING_REASONS:
                continue

            message = waiting.get("message") or ""
            if self._is_entrypoint_permission_message(message):
                messages.append(message)
        return messages

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not timeline_has_event(timeline, kind="Generic", phase="Failure"):
            return False

        matched_events = self._matching_events(timeline)
        waiting_messages = self._matching_waiting_messages(pod)

        if not matched_events:
            return False

        if not waiting_messages and not any(
            status.get("state", {}).get("waiting", {}).get("reason")
            in self.WAITING_REASONS
            for status in pod.get("status", {}).get("containerStatuses", []) or []
        ):
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: self._is_entrypoint_permission_message(str(e.get("message", "")))
        )

        if total_failures < 2 and duration < 30 and not waiting_messages:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        messages = [
            (event.get("message") or "")
            for event in matched_events
            for _ in range(self._occurrences(event))
        ]
        messages.extend(self._matching_waiting_messages(pod))

        dominant_msg = max(set(messages), key=messages.count) if messages else None

        chain = CausalChain(
            causes=[
                Cause(
                    code="ENTRYPOINT_EXECUTION_ATTEMPTED",
                    message="Container runtime attempted to execute the configured entrypoint or startup command",
                    role="execution_context",
                ),
                Cause(
                    code="ENTRYPOINT_PERMISSION_DENIED",
                    message="Entrypoint or startup script exists but is not executable by the container runtime",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_NEVER_STARTS",
                    message="Container remains stuck before successful startup",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container entrypoint exists but cannot be executed due to permission denial",
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Kubelet or runtime reports exec-style permission denied while starting the container",
                "Container remains in a waiting startup error state",
                *(["Dominant exec error: " + dominant_msg] if dominant_msg else []),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because the configured entrypoint is not executable"
                ]
            },
            "likely_causes": [
                "Entrypoint script or binary lacks execute permission in the image",
                "Image build copied the startup script without preserving executable mode",
                "Container runs as a user that cannot execute the configured entrypoint",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect the image entrypoint or command and file permissions",
                "Verify the startup script is executable in the built image",
                "Check the container user and filesystem ownership of the entrypoint",
            ],
        }
