from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import parse_time


class CrashLoopAfterImageUpdateRule(FailureRule):
    """
    Detects CrashLoopBackOff that starts shortly after kubelet pulls a fresh
    image for the same container.

    Real-world behavior:
    - kubelet emits Pulling/Pulled when it actually fetches a new image
    - the container usually gets Created/Started before the crashloop begins
    - BackOff plus CrashLoopBackOff status indicates the new image starts but
      fails repeatedly at runtime

    This is an inferred causal correlation, not a deterministic proof, so the
    rule stays non-deterministic and lets stronger root causes such as OOMKilled
    or probe failures win by priority.
    """

    name = "CrashLoopAfterImageUpdate"
    category = "Compound"
    priority = 54
    deterministic = False

    phases = ["Pending", "Running"]
    container_states = ["waiting", "terminated"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ImagePullError",
        "InvalidEntrypoint",
        "EntrypointPermissionDenied",
    ]

    FRESH_PULL_REASON = "Pulled"
    CRASH_EVENT_REASON = "BackOff"
    START_REASONS = {"Created", "Started", "SuccessfulCreate"}
    EXCLUSION_REASONS = {"ErrImagePull", "ImagePullBackOff", "Unhealthy", "FailedMount"}

    MAX_CRASH_DELAY_SECONDS = 600
    MIN_CRASH_DELAY_SECONDS = 1
    TERMINAL_RUNTIME_REASONS = {"Error", "ContainerCannotRun"}

    EXECUTION_EXCLUSION_MARKERS = (
        "permission denied",
        "no such file or directory",
        "executable file not found",
        "exec format error",
    )

    def _extract_timestamp(self, event: dict):
        timestamp = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not timestamp:
            return None

        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _extract_crash_onset(self, event: dict):
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

    def _crashing_statuses(self, pod: dict) -> list[dict]:
        statuses = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                statuses.append(status)
        return statuses

    def _container_images(self, pod: dict) -> dict[str, str]:
        return {
            container.get("name"): container.get("image", "")
            for container in pod.get("spec", {}).get("containers", []) or []
            if container.get("name")
        }

    def _has_oom_signal(self, pod: dict) -> bool:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            terminated = status.get("lastState", {}).get("terminated") or {}
            if terminated.get("reason") == "OOMKilled":
                return True
        return False

    def _fresh_pull_events(self, timeline, image_ref: str) -> list[dict]:
        image_ref = (image_ref or "").lower()
        if not image_ref:
            return []

        matches = []
        for event in timeline.raw_events:
            if event.get("reason") != self.FRESH_PULL_REASON:
                continue

            message = str(event.get("message", "")).lower()
            if image_ref not in message:
                continue
            if "already present on machine" in message:
                continue
            if "successfully pulled image" not in message:
                continue

            matches.append(event)

        return matches

    def _start_signal_between(
        self,
        timeline,
        container_name: str,
        update_ts,
        crash_ts,
    ) -> bool:
        container_name = (container_name or "").lower()

        for event in timeline.raw_events:
            if event.get("reason") not in self.START_REASONS:
                continue

            ts = self._extract_timestamp(event)
            if ts is None or ts <= update_ts or ts > crash_ts:
                continue

            if not container_name:
                return True

            message = str(event.get("message", "")).lower()
            if container_name in message:
                return True

        return False

    def _runtime_failure_signal(self, status: dict) -> bool:
        terminated = status.get("lastState", {}).get("terminated") or {}
        restart_count = status.get("restartCount", 0) or 0

        return (
            restart_count > 0
            and terminated.get("reason") in self.TERMINAL_RUNTIME_REASONS
        )

    def _container_scoped_message(self, event: dict, container_name: str) -> bool:
        container_name = (container_name or "").lower()
        if not container_name:
            return True

        message = str(event.get("message", "")).lower()
        return container_name in message

    def _first_crash_event_after(self, timeline, container_name: str, update_ts):
        first_event = None
        first_ts = None

        for event in timeline.raw_events:
            if event.get("reason") != self.CRASH_EVENT_REASON:
                continue
            if not self._container_scoped_message(event, container_name):
                continue

            ts = self._extract_crash_onset(event)
            if ts is None or ts <= update_ts:
                continue

            if first_ts is None or ts < first_ts:
                first_event = event
                first_ts = ts

        return first_event, first_ts

    def _has_exclusion_signal(self, timeline, update_ts, crash_ts) -> bool:
        for event in timeline.raw_events:
            ts = self._extract_timestamp(event)
            if ts is None or ts < update_ts or ts > crash_ts:
                continue

            if event.get("reason") in self.EXCLUSION_REASONS:
                return True

            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.EXECUTION_EXCLUSION_MARKERS):
                return True

        return False

    def _correlated_rollout(self, pod: dict, timeline):
        if self._has_oom_signal(pod):
            return None

        image_map = self._container_images(pod)
        statuses = sorted(
            self._crashing_statuses(pod),
            key=lambda status: status.get("restartCount", 0) or 0,
            reverse=True,
        )

        for status in statuses:
            container_name = status.get("name", "")
            image_ref = image_map.get(container_name, "")
            fresh_pulls = self._fresh_pull_events(timeline, image_ref)

            if not fresh_pulls:
                continue

            for pull_event in sorted(
                fresh_pulls,
                key=lambda event: self._extract_timestamp(event)
                or parse_time("1970-01-01T00:00:00+00:00"),
                reverse=True,
            ):
                update_ts = self._extract_timestamp(pull_event)
                if update_ts is None:
                    continue

                crash_event, crash_ts = self._first_crash_event_after(
                    timeline,
                    container_name,
                    update_ts,
                )
                if crash_event is None or crash_ts is None:
                    continue

                crash_delay = (crash_ts - update_ts).total_seconds()
                if (
                    crash_delay < self.MIN_CRASH_DELAY_SECONDS
                    or crash_delay > self.MAX_CRASH_DELAY_SECONDS
                ):
                    continue

                if self._has_exclusion_signal(timeline, update_ts, crash_ts):
                    continue

                if not self._start_signal_between(
                    timeline,
                    container_name,
                    update_ts,
                    crash_ts,
                ) and not self._runtime_failure_signal(status):
                    continue

                return {
                    "container_name": container_name or "<unknown>",
                    "image_ref": image_ref or "<unknown>",
                    "pull_event": pull_event,
                    "crash_event": crash_event,
                    "update_ts": update_ts,
                    "crash_ts": crash_ts,
                    "crash_delay": crash_delay,
                    "restart_count": status.get("restartCount", 0) or 0,
                }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        return self._correlated_rollout(pod, timeline) is not None

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        correlation = self._correlated_rollout(pod, timeline) if timeline else None

        container_name = correlation["container_name"] if correlation else "<unknown>"
        image_ref = correlation["image_ref"] if correlation else "<unknown>"
        crash_delay = correlation["crash_delay"] if correlation else None
        restart_count = correlation["restart_count"] if correlation else 0

        chain = CausalChain(
            causes=[
                Cause(
                    code="FRESH_IMAGE_PULL_COMPLETED",
                    message="Kubelet completed a fresh pull of the image now used by the crashing container",
                    role="image_context",
                ),
                Cause(
                    code="NEW_IMAGE_RUNTIME_REGRESSION",
                    message="The newly pulled image starts and then fails repeatedly at runtime",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CRASHLOOP",
                    message="Pod entered CrashLoopBackOff after the image update",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoop began after a recent image update",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                "A fresh successful image pull was recorded for the container that is now crashlooping",
                "CrashLoopBackOff started after the new image was pulled in the same pod lifecycle",
                *(
                    [
                        f"First BackOff event followed the successful pull by {crash_delay:.1f}s"
                    ]
                    if crash_delay is not None
                    else []
                ),
            ],
            "likely_causes": [
                "The new image introduced an application regression that causes immediate startup failure",
                "The updated image changed runtime dependencies, configuration defaults, or bundled assets",
                "The rollout switched to a bad build even though the image pulled successfully",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "CrashLoopBackOff began shortly after kubelet pulled a fresh image"
                ],
                f"container:{container_name}": [
                    f"Container restarted {restart_count} times after image '{image_ref}' was freshly pulled"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect logs from the crashing container revision",
                "Compare the new image digest with the previous known-good rollout",
                "Roll back to the previous image and confirm whether the crashloop stops",
                "Review application startup changes introduced by the new image build",
            ],
            "blocking": True,
        }
