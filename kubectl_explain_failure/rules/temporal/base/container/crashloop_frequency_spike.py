from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CrashLoopFrequencySpikeRule(FailureRule):
    """
    Detects a crashloop that is accelerating relative to its own recent baseline.

    Real-world behavior:
    - Kubernetes commonly coalesces repeated BackOff events into a single event
      object with `count`, `firstTimestamp`, and `lastTimestamp`
    - a spike is not just "many restarts", but a materially higher recent rate
      than the immediately preceding window
    - the Pod must still be actively crashlooping so the rule does not diagnose
      stale historical noise
    """

    name = "CrashLoopFrequencySpike"
    category = "Temporal"
    priority = 78
    deterministic = False

    phases = ["Running", "Failed", "CrashLoopBackOff"]
    container_states = ["waiting"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
        "RapidRestartEscalation",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 10
    MIN_RECENT_OCCURRENCES = 5
    MIN_BASELINE_OCCURRENCES = 2
    MIN_SPIKE_RATIO = 2.0
    MIN_OCCURRENCE_DELTA = 3
    MIN_RESTART_COUNT = 6
    BACKOFF_REASONS = {"BackOff", "CrashLoopBackOff"}

    def _occurrences(self, event: dict[str, Any]) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _first_timestamp(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _last_timestamp(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _reference_time(self, timeline: Timeline) -> datetime:
        try:
            return timeline._reference_time()
        except Exception:
            for event in reversed(timeline.raw_events):
                timestamp = self._last_timestamp(event) or self._first_timestamp(event)
                if timestamp is not None:
                    return timestamp
        return datetime.now(timezone.utc)

    def _crashlooping_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        statuses = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                statuses.append(status)
        return statuses

    def _backoff_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.raw_events
            if event.get("reason") in self.BACKOFF_REASONS
        ]

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _relevant_events(
        self,
        timeline: Timeline,
        *,
        container_name: str,
        crashlooping_names: list[str],
    ) -> list[dict[str, Any]]:
        container_name = (container_name or "").lower()
        crashlooping_names = [name.lower() for name in crashlooping_names if name]
        backoff_events = self._backoff_events(timeline)
        if not backoff_events:
            return []

        named_events_present = any(
            any(name in self._event_message(event) for name in crashlooping_names)
            for event in backoff_events
        )

        if named_events_present:
            return [
                event
                for event in backoff_events
                if container_name and container_name in self._event_message(event)
            ]

        if len(crashlooping_names) == 1:
            return backoff_events

        return []

    def _occurrence_timestamps(self, event: dict[str, Any]) -> list[datetime]:
        occurrences = self._occurrences(event)
        first_ts = self._first_timestamp(event)
        last_ts = self._last_timestamp(event)

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

    def _window_profile(
        self,
        timeline: Timeline,
        relevant_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        reference = self._reference_time(timeline)
        recent_start = reference - timedelta(minutes=self.WINDOW_MINUTES)
        prior_start = recent_start - timedelta(minutes=self.WINDOW_MINUTES)

        recent_occurrences = 0
        prior_occurrences = 0
        recent_times: list[datetime] = []
        prior_times: list[datetime] = []

        for event in relevant_events:
            for occurrence_ts in self._occurrence_timestamps(event):
                if occurrence_ts > reference:
                    continue
                if recent_start <= occurrence_ts <= reference:
                    recent_occurrences += 1
                    recent_times.append(occurrence_ts)
                elif prior_start <= occurrence_ts < recent_start:
                    prior_occurrences += 1
                    prior_times.append(occurrence_ts)

        observed = sorted(prior_times + recent_times)
        observed_duration_seconds = 0.0
        if len(observed) >= 2:
            observed_duration_seconds = (observed[-1] - observed[0]).total_seconds()

        return {
            "reference": reference,
            "recent_occurrences": recent_occurrences,
            "prior_occurrences": prior_occurrences,
            "recent_times": recent_times,
            "prior_times": prior_times,
            "observed_duration_seconds": observed_duration_seconds,
        }

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        crashlooping = self._crashlooping_statuses(pod)
        if not crashlooping:
            return None

        crashlooping_names = [
            str(status.get("name", "")) for status in crashlooping if status.get("name")
        ]

        if not timeline.events_within_window(self.WINDOW_MINUTES, reason="BackOff"):
            recent_crashloop_events = timeline.events_within_window(
                self.WINDOW_MINUTES, reason="CrashLoopBackOff"
            )
            if not recent_crashloop_events:
                return None

        best: dict[str, Any] | None = None

        for status in crashlooping:
            restart_count = status.get("restartCount", 0) or 0
            if restart_count < self.MIN_RESTART_COUNT:
                continue

            container_name = str(status.get("name", "") or "<unknown>")
            relevant_events = self._relevant_events(
                timeline,
                container_name=container_name,
                crashlooping_names=crashlooping_names,
            )
            if not relevant_events:
                continue

            profile = self._window_profile(timeline, relevant_events)
            recent_occurrences = profile["recent_occurrences"]
            prior_occurrences = profile["prior_occurrences"]

            if recent_occurrences < self.MIN_RECENT_OCCURRENCES:
                continue
            if prior_occurrences < self.MIN_BASELINE_OCCURRENCES:
                continue

            spike_ratio = recent_occurrences / max(prior_occurrences, 1)
            if spike_ratio < self.MIN_SPIKE_RATIO:
                continue
            if (recent_occurrences - prior_occurrences) < self.MIN_OCCURRENCE_DELTA:
                continue

            if profile["observed_duration_seconds"] < self.WINDOW_MINUTES * 60:
                continue

            candidate = {
                "container_name": container_name,
                "restart_count": restart_count,
                "recent_occurrences": recent_occurrences,
                "prior_occurrences": prior_occurrences,
                "spike_ratio": spike_ratio,
                "observed_duration_seconds": profile["observed_duration_seconds"],
            }

            if best is None:
                best = candidate
                continue

            best_key = (best["spike_ratio"], best["recent_occurrences"])
            candidate_key = (candidate["spike_ratio"], candidate["recent_occurrences"])
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CrashLoopFrequencySpike requires a Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("CrashLoopFrequencySpike explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        restart_count = candidate["restart_count"]
        recent_occurrences = candidate["recent_occurrences"]
        prior_occurrences = candidate["prior_occurrences"]
        spike_ratio = candidate["spike_ratio"]
        observed_minutes = candidate["observed_duration_seconds"] / 60

        chain = CausalChain(
            causes=[
                Cause(
                    code="CRASHLOOP_ACTIVE",
                    message=f"Container '{container_name}' is currently in CrashLoopBackOff",
                    role="workload_context",
                ),
                Cause(
                    code="RECENT_BACKOFF_RATE_SPIKE",
                    message=f"BackOff occurrences increased from {prior_occurrences} to {recent_occurrences} across consecutive {self.WINDOW_MINUTES}-minute windows",
                    role="temporal_context",
                ),
                Cause(
                    code="CRASHLOOP_ACCELERATING",
                    message="Kubelet restart backoff is accelerating rather than staying at a stable failure rate",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_STABILITY_DEGRADING",
                    message="The Pod is becoming less stable as crash frequency increases",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoop restart frequency spiked sharply relative to the prior baseline",
            "confidence": 0.91,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Container '{container_name}' is currently waiting in CrashLoopBackOff with restartCount={restart_count}",
                f"Estimated recent BackOff frequency: {recent_occurrences} occurrences in the last {self.WINDOW_MINUTES} minutes",
                f"Estimated prior BackOff frequency: {prior_occurrences} occurrences in the preceding {self.WINDOW_MINUTES} minutes",
                f"Recent crashloop rate is {spike_ratio:.1f}x higher than the prior baseline",
                f"BackOff acceleration observed across {observed_minutes:.1f} minutes of timeline history",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"CrashLoop restart rate increased from {prior_occurrences} to {recent_occurrences} occurrences across consecutive windows"
                ],
                f"container:{container_name}": [
                    f"Container restartCount={restart_count} while current state remains CrashLoopBackOff"
                ],
            },
            "likely_causes": [
                "A recent rollout, config change, or dependency regression made the container fail faster than before",
                "The application is reaching the same failure condition earlier in startup than it did in the prior window",
                "An external dependency or credential issue degraded and is now triggering denser restart backoff events",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                "Compare the spike window with recent deploy, config, secret, or dependency changes",
                "Inspect restart timestamps and application logs to identify what changed just before the spike",
            ],
        }
