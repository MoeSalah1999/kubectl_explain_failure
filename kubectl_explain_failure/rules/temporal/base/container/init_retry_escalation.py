from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class InitRetryEscalationRule(FailureRule):
    """
    Detects init-container retry behavior that has escalated into a sustained
    kubelet backoff loop instead of a transient startup hiccup.

    Real-world behavior:
    - kubelet retries a failing init container until it completes successfully
    - repeated init failures are often coalesced into BackOff events with
      count/firstTimestamp/lastTimestamp rather than one event per retry
    - during this loop the main workload remains stuck in PodInitializing or
      ContainerCreating because kubelet cannot advance past init completion
    """

    name = "InitRetryEscalation"
    category = "Temporal"
    priority = 74
    deterministic = False

    phases = ["Pending", "Init", "CrashLoopBackOff"]
    container_states = ["waiting", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "InitContainerBlocksMain",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 20
    MIN_BACKOFF_OCCURRENCES = 4
    MIN_RESTART_COUNT = 3
    MIN_OBSERVED_DURATION_SECONDS = 300
    MAIN_WAITING_REASONS = {"PodInitializing", "ContainerCreating"}
    CACHE_KEY = "_init_retry_escalation_candidate"

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_start(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            return max(int(raw_count), 1)
        except Exception:
            return 1

    def _occurrence_timestamps(self, event: dict[str, Any]) -> list[datetime]:
        occurrences = self._occurrences(event)
        first_ts = self._event_start(event)
        last_ts = self._event_end(event)

        if first_ts is None and last_ts is None:
            return []

        anchor = last_ts or first_ts
        if anchor is None:
            return []

        if (
            occurrences <= 1
            or first_ts is None
            or last_ts is None
            or last_ts <= first_ts
        ):
            return [anchor for _ in range(occurrences)]

        step = (last_ts - first_ts) / (occurrences - 1)
        return [first_ts + (step * index) for index in range(occurrences)]

    def _blocked_main_containers(
        self, pod: dict[str, Any]
    ) -> list[dict[str, str]] | None:
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        if not spec_containers:
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        statuses_by_name = {
            str(status.get("name", "")): status
            for status in statuses
            if status.get("name")
        }

        blocked: list[dict[str, str]] = []
        for container in spec_containers:
            name = str(container.get("name", ""))
            if not name:
                continue

            status = statuses_by_name.get(name, {})
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}

            if state.get("running") or state.get("terminated"):
                return None

            if int(status.get("restartCount", 0) or 0) > 0:
                return None

            waiting_reason = str(waiting.get("reason", "") or "PodInitializing")
            if waiting_reason not in self.MAIN_WAITING_REASONS:
                return None

            blocked.append({"name": name, "reason": waiting_reason})

        return blocked or None

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _relevant_backoff_events(
        self,
        timeline: Timeline,
        *,
        init_container_name: str,
        failing_init_names: list[str],
    ) -> list[dict[str, Any]]:
        lowered_name = init_container_name.lower()
        failing_init_names = [name.lower() for name in failing_init_names if name]

        backoff_events = [
            event
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")) == "BackOff"
        ]
        if not backoff_events:
            return []

        named_present = any(
            any(name in self._event_message(event) for name in failing_init_names)
            or "failed init container" in self._event_message(event)
            for event in backoff_events
        )

        if named_present:
            return [
                event
                for event in backoff_events
                if lowered_name in self._event_message(event)
                or "failed init container" in self._event_message(event)
            ]

        if len(failing_init_names) == 1:
            return backoff_events

        return []

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        blocked_main = self._blocked_main_containers(pod)
        if not blocked_main:
            return None

        init_statuses = pod.get("status", {}).get("initContainerStatuses", []) or []
        failing_init_statuses = []
        for status in init_statuses:
            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") != "CrashLoopBackOff":
                continue

            restart_count = int(status.get("restartCount", 0) or 0)
            if restart_count < self.MIN_RESTART_COUNT:
                continue

            failing_init_statuses.append(status)

        if not failing_init_statuses:
            return None

        failing_names = [
            str(status.get("name", "")) for status in failing_init_statuses
        ]
        best: dict[str, Any] | None = None

        for status in failing_init_statuses:
            container_name = str(status.get("name", "") or "<unknown>")
            relevant_events = self._relevant_backoff_events(
                timeline,
                init_container_name=container_name,
                failing_init_names=failing_names,
            )
            if not relevant_events:
                continue

            occurrence_times = sorted(
                occurrence_ts
                for event in relevant_events
                for occurrence_ts in self._occurrence_timestamps(event)
            )
            occurrences = len(occurrence_times)
            if occurrences < self.MIN_BACKOFF_OCCURRENCES:
                continue

            observed_duration_seconds = 0.0
            if len(occurrence_times) >= 2:
                observed_duration_seconds = (
                    occurrence_times[-1] - occurrence_times[0]
                ).total_seconds()
            if observed_duration_seconds < self.MIN_OBSERVED_DURATION_SECONDS:
                continue

            restart_count = int(status.get("restartCount", 0) or 0)
            latest_event = max(
                relevant_events,
                key=lambda event: self._event_end(event)
                or self._event_start(event)
                or parse_time("1970-01-01T00:00:00+00:00"),
            )

            candidate = {
                "container_name": container_name,
                "restart_count": restart_count,
                "occurrences": occurrences,
                "observed_duration_seconds": observed_duration_seconds,
                "latest_message": str(latest_event.get("message", "")).strip(),
                "blocked_main": blocked_main,
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["occurrences"],
                best["restart_count"],
                best["observed_duration_seconds"],
            )
            candidate_key = (
                candidate["occurrences"],
                candidate["restart_count"],
                candidate["observed_duration_seconds"],
            )
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("InitRetryEscalation requires a Timeline context")

        candidate = context.get(self.CACHE_KEY) or self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("InitRetryEscalation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        init_name = candidate["container_name"]
        main_name = candidate["blocked_main"][0]["name"]
        main_reason = candidate["blocked_main"][0]["reason"]
        restart_count = candidate["restart_count"]
        occurrences = candidate["occurrences"]
        span_minutes = candidate["observed_duration_seconds"] / 60

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_RETRY_LOOP_OBSERVED",
                    message=f"Init container '{init_name}' is still retrying and has not completed initialization",
                    role="workload_context",
                ),
                Cause(
                    code="REPEATED_INIT_BACKOFF_EPISODES",
                    message=f"Kubelet recorded {occurrences} recent init-container retry occurrence(s) for '{init_name}' within the active incident window",
                    role="temporal_context",
                ),
                Cause(
                    code="INIT_RETRY_PATTERN_ESCALATING",
                    message="Init retries have escalated into a sustained backoff loop rather than a transient startup failure",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="MAIN_CONTAINERS_STILL_BLOCKED_BY_INIT",
                    message=f"Main container '{main_name}' is still blocked because init completion never stabilizes",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Init container retries escalated into a sustained kubelet backoff loop",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Init container '{init_name}' is currently waiting in CrashLoopBackOff with restartCount={restart_count}",
                f"Estimated recent init retry frequency: {occurrences} BackOff occurrence(s) within the last {self.WINDOW_MINUTES} minutes",
                f"Main container '{main_name}' has not started and remains waiting: {main_reason}",
                f"Init retry escalation persisted across {span_minutes:.1f} minutes of recent timeline history",
                f"Latest init retry message: {candidate['latest_message']}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"Pod remained stuck in initialization while init retry activity persisted for {span_minutes:.1f} minutes"
                ],
                f"container:{init_name}": [
                    f"Init container restartCount={restart_count} with {occurrences} recent BackOff occurrence(s)"
                ],
                f"container:{main_name}": [
                    f"Main container is still waiting with reason {main_reason}"
                ],
            },
            "likely_causes": [
                "The init script keeps retrying a dependency that is still unavailable or misconfigured",
                "Bootstrap logic now fails quickly enough that kubelet backoff is compounding within the same incident window",
                "A recent image, config, or secret change made init-container startup failures persistent instead of transient",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {init_name} --previous",
                "Compare the retry window with recent dependency, config, and image changes used by the init container",
                "Inspect whether the init step is failing fast on the same operation and should fail clearly instead of endlessly retrying",
            ],
        }
