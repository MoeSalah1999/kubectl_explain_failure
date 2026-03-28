from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event


class ContainerStartTimeoutRule(FailureRule):
    """
    Detects container startup attempts that time out before the runtime can
    transition the container into a started state.

    Real-world behavior:
    - kubelet often reports a `Failed` event with text like
      `context deadline exceeded`, `timed out`, or `StartContainer`
    - the container typically remains in ContainerCreating,
      CreateContainerError, or RunContainerError while retries continue
    - this is narrower than a generic runtime start failure and should win
      when the runtime failure is explicitly timeout-shaped
    """

    name = "ContainerStartTimeout"
    category = "Container"
    priority = 85
    deterministic = True

    phases = ["Pending"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    blocks = ["ContainerRuntimeStartFailure"]

    TIMEOUT_MARKERS = (
        "context deadline exceeded",
        "deadline exceeded",
        "timed out",
        "timeout exceeded",
    )

    START_CONTEXT_MARKERS = (
        "failed to start container",
        "startcontainer",
        "starting container",
        "create container",
        "createcontainer",
        "containerd task",
        "shim task",
    )

    EXCLUSION_MARKERS = (
        "permission denied",
        "exec format error",
        "no such file or directory",
        "not found",
        "pull access denied",
        "manifest unknown",
        "imagepullbackoff",
        "errimagepull",
    )

    WAITING_REASONS = {
        "ContainerCreating",
        "CreateContainerError",
        "RunContainerError",
    }

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_timeout_start_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        has_timeout = any(marker in msg for marker in self.TIMEOUT_MARKERS)
        has_start_context = any(marker in msg for marker in self.START_CONTEXT_MARKERS)
        return has_timeout and has_start_context

    def _matching_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            if self._is_timeout_start_message(str(event.get("message", ""))):
                matches.append(event)
        return matches

    def _has_waiting_start_state(self, pod: dict) -> bool:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") in self.WAITING_REASONS:
                return True
        return False

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
        if not matched_events:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: self._is_timeout_start_message(str(e.get("message", "")))
        )

        if total_failures < 2 and duration < 60:
            return False

        if not self._has_waiting_start_state(pod):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [
                (event.get("message") or "")
                for event in matched_events
                for _ in range(self._occurrences(event))
            ]
            dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_START_REQUESTED",
                    message="Kubelet requested that the runtime start the container",
                    role="execution_context",
                ),
                Cause(
                    code="CONTAINER_START_TIMEOUT",
                    message="Container runtime exceeded the allowed time while starting the container",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STUCK_STARTING",
                    message="Pod remains stuck before container startup completes",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Container runtime timed out while starting the container",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Kubelet failure events explicitly show container start timeout markers",
                "Container remains in a waiting startup state while timeout events repeat",
                *(["Dominant timeout error: " + dominant_msg] if dominant_msg else []),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is stuck because container startup timed out in the runtime"
                ]
            },
            "likely_causes": [
                "containerd or CRI-O is overloaded or unhealthy on the node",
                "Runtime shim startup is hanging",
                "Node resource pressure is delaying runtime startup beyond kubelet deadlines",
                "Security or storage hooks in the start path are blocking container launch",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check kubelet logs for start timeout or deadline exceeded errors",
                "Verify containerd or CRI-O health on the node",
                "Inspect node resource pressure and runtime shim behavior",
            ],
        }
