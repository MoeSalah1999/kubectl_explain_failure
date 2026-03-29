from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import parse_time


class OOMKilledThenCrashLoopRule(FailureRule):
    """
    Detects a concrete OOMKilled termination that then progresses into
    CrashLoopBackOff for the same container.

    Real-world behavior:
    - kubelet records the last termination as OOMKilled
    - the pod restarts the container and begins emitting BackOff events
    - the pod settles into CrashLoopBackOff while restartCount grows

    This is intentionally stricter than the existing CrashLoopOOMKilled rule:
    it requires timestamped termination data so the engine can prove that the
    restart backoff began after the OOM kill rather than merely coexisting with it.
    """

    name = "OOMKilledThenCrashLoop"
    category = "Compound"
    priority = 67
    deterministic = True

    phases = ["Running"]
    container_states = ["waiting", "terminated"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
        "OOMKilled",
    ]

    MAX_CRASH_DELAY_SECONDS = 600
    CRASH_REASON = "BackOff"

    def _event_timestamp(self, event: dict):
        timestamp = (
            event.get("eventTime")
            or event.get("firstTimestamp")
            or event.get("lastTimestamp")
            or event.get("timestamp")
        )
        if not timestamp:
            return None
        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _terminated_at(self, status: dict):
        terminated = status.get("lastState", {}).get("terminated") or {}
        timestamp = terminated.get("finishedAt")
        if not timestamp:
            return None
        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _crashloop_waiting(self, status: dict) -> bool:
        waiting = status.get("state", {}).get("waiting") or {}
        return waiting.get("reason") == "CrashLoopBackOff"

    def _backoff_events(self, timeline, container_name: str) -> list[dict]:
        container_name = (container_name or "").lower()
        matches = []

        for event in timeline.raw_events:
            if event.get("reason") != self.CRASH_REASON:
                continue

            message = str(event.get("message", "")).lower()
            if container_name and container_name not in message:
                continue

            matches.append(event)

        return matches

    def _correlated_status(self, pod: dict, timeline):
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            terminated = status.get("lastState", {}).get("terminated") or {}
            if terminated.get("reason") != "OOMKilled":
                continue

            terminated_at = self._terminated_at(status)
            if terminated_at is None:
                continue

            if not self._crashloop_waiting(status):
                continue

            restart_count = status.get("restartCount", 0) or 0
            if restart_count < 1:
                continue

            container_name = status.get("name", "")
            backoffs = self._backoff_events(timeline, container_name)
            if not backoffs:
                continue

            first_backoff = min(
                backoffs,
                key=lambda event: self._event_timestamp(event)
                or parse_time("1970-01-01T00:00:00+00:00"),
            )
            first_backoff_ts = self._event_timestamp(first_backoff)
            if first_backoff_ts is None:
                continue

            delay = (first_backoff_ts - terminated_at).total_seconds()
            if delay < 0 or delay > self.MAX_CRASH_DELAY_SECONDS:
                continue

            return {
                "container_name": container_name or "<unknown>",
                "restart_count": restart_count,
                "terminated": terminated,
                "delay": delay,
            }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return self._correlated_status(pod, timeline) is not None

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        correlation = self._correlated_status(pod, timeline) if timeline else None

        container_name = (
            correlation["container_name"] if correlation else "<unknown>"
        )
        restart_count = correlation["restart_count"] if correlation else 0
        terminated = correlation["terminated"] if correlation else {}
        delay = correlation["delay"] if correlation else None
        exit_code = terminated.get("exitCode")

        chain = CausalChain(
            causes=[
                Cause(
                    code="OOM_TERMINATION_OBSERVED",
                    message="The container's most recent termination was caused by OOMKilled",
                    role="resource_context",
                ),
                Cause(
                    code="MEMORY_PRESSURE_REPEATEDLY_KILLS_CONTAINER",
                    message="The workload keeps exceeding its memory limit and cannot stay up long enough to stabilize",
                    role="resource_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASHLOOP_AFTER_OOM",
                    message="Kubelet enters restart backoff after the OOMKilled termination",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "OOMKilled termination escalated into CrashLoopBackOff",
            "confidence": 0.98,
            "causes": chain,
            "evidence": [
                "Container lastState shows OOMKilled before the current CrashLoopBackOff state",
                "Kubelet emitted BackOff restart events for the same crashing container",
                *(
                    [f"First BackOff event started {delay:.1f}s after the recorded OOMKilled termination"]
                    if delay is not None
                    else []
                ),
                *(
                    [f"OOMKilled termination exit code was {exit_code}"]
                    if exit_code is not None
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is in CrashLoopBackOff after an OOMKilled container termination"
                ],
                f"container:{container_name}": [
                    f"Container restarted {restart_count} times after being OOMKilled"
                ],
            },
            "likely_causes": [
                "Container memory limit is too low for the workload's startup or steady-state usage",
                "The application has a memory spike or leak that repeatedly triggers kernel OOM enforcement",
                "A recent code or traffic change increased memory consumption beyond the configured limit",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Review container memory requests and limits",
                "Inspect memory usage around startup and peak load",
                "Check whether a recent deployment changed workload memory behavior",
                "Raise the memory limit temporarily to confirm the crashloop is OOM-driven",
            ],
            "blocking": True,
        }
