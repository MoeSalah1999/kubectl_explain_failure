from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DelayedRootCauseDetectionRule(FailureRule):
    """
    Explains when the engine's final root cause only became visible after
    earlier ambiguous symptoms.

    Real-world behavior:
    - kubelet, scheduler, and controllers often emit generic symptoms before a
      specific failure signature is available
    - image pulls can begin as Pulling/Failed/BackOff events before the registry
      returns a decisive manifest-not-found response
    - this rule preserves the selected root cause and adds temporal context so
      operators understand why earlier events were symptoms rather than the
      final diagnosis
    """

    name = "DelayedRootCauseDetection"
    category = "Temporal"
    priority = 5
    deterministic = True
    post_resolution = True
    augment_only = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 60
    MIN_DELAY_MINUTES = 10
    CACHE_KEY = "_delayed_root_cause_detection_candidate"

    AMBIGUOUS_SYMPTOM_REASONS = {
        "BackOff",
        "Failed",
        "FailedScheduling",
        "Pulling",
        "SandboxChanged",
        "Unhealthy",
    }

    MANIFEST_MARKERS = (
        "manifest unknown",
        "manifest for ",
        "failed to resolve reference",
        "not found: manifest unknown",
    )

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        raw = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "") or "").lower()

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "") or "").strip()

    def _manifest_unknown_event(self, event: dict[str, Any]) -> bool:
        if self._reason(event) not in {"ErrImagePull", "ImagePullBackOff", "Failed"}:
            return False
        message = self._message(event)
        return any(marker in message for marker in self.MANIFEST_MARKERS)

    def _image_backoff_event(self, event: dict[str, Any]) -> bool:
        return self._reason(event) == "ImagePullBackOff"

    def _readiness_probe_event(self, event: dict[str, Any]) -> bool:
        message = self._message(event)
        return self._reason(event) == "Unhealthy" and "readiness probe" in message

    def _liveness_probe_event(self, event: dict[str, Any]) -> bool:
        message = self._message(event)
        return self._reason(event) == "Unhealthy" and "liveness probe" in message

    def _root_event_filter(
        self,
        winner_name: str,
        winner_root_cause: str,
    ) -> Callable[[dict[str, Any]], bool] | None:
        root_text = f"{winner_name} {winner_root_cause}".lower()
        if "manifest" in root_text:
            return self._manifest_unknown_event
        if "imagepullbackoff" in root_text or "image pull" in root_text:
            return self._image_backoff_event
        if "readiness" in root_text:
            return self._readiness_probe_event
        if "liveness" in root_text:
            return self._liveness_probe_event
        return None

    def _is_ambiguous_symptom(
        self,
        event: dict[str, Any],
        root_filter: Callable[[dict[str, Any]], bool],
    ) -> bool:
        if root_filter(event):
            return False
        reason = self._reason(event)
        if reason in self.AMBIGUOUS_SYMPTOM_REASONS:
            return True

        message = self._message(event)
        return any(
            marker in message
            for marker in (
                "waiting",
                "retrying",
                "back-off",
                "timed out",
                "context deadline exceeded",
                "still creating",
            )
        )

    def _candidate(self, context: dict[str, Any]) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        engine_state = context.get("_engine_state", {}) or {}
        preliminary = engine_state.get("preliminary_result") or {}
        winner_match = engine_state.get("winner_match")
        if not isinstance(preliminary, dict) or not isinstance(winner_match, dict):
            return None

        resolution = preliminary.get("resolution") or {}
        winner_name = str(resolution.get("winner", "")).strip()
        if not winner_name:
            return None

        winner_root_cause = str(
            winner_match.get("root_cause") or preliminary.get("root_cause") or ""
        ).strip()
        if not winner_root_cause:
            return None

        root_filter = self._root_event_filter(winner_name, winner_root_cause)
        if root_filter is None:
            return None

        ordered = self._ordered_recent_events(timeline)
        if len(ordered) < 2:
            return None

        first_root_index = None
        first_root_event = None
        for index, event in enumerate(ordered):
            if root_filter(event):
                first_root_index = index
                first_root_event = event
                break

        if (
            first_root_index is None
            or first_root_event is None
            or first_root_index == 0
        ):
            return None

        earlier_symptoms = [
            event
            for event in ordered[:first_root_index]
            if self._is_ambiguous_symptom(event, root_filter)
        ]
        if not earlier_symptoms:
            return None

        first_symptom = earlier_symptoms[0]
        first_symptom_time = self._event_time(first_symptom)
        first_root_time = self._event_time(first_root_event)
        if first_symptom_time is None or first_root_time is None:
            return None

        delay_seconds = (first_root_time - first_symptom_time).total_seconds()
        delay_minutes = delay_seconds / 60.0
        if delay_minutes < self.MIN_DELAY_MINUTES:
            return None

        return {
            "preliminary": preliminary,
            "winner_name": winner_name,
            "winner_root_cause": winner_root_cause,
            "first_symptom": first_symptom,
            "first_root_event": first_root_event,
            "delay_minutes": delay_minutes,
            "symptom_count": len(earlier_symptoms),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(context)
        if candidate is None:
            raise ValueError("DelayedRootCauseDetection explain() called without match")

        preliminary = candidate["preliminary"]
        winner_name = str(candidate["winner_name"])
        winner_root_cause = str(candidate["winner_root_cause"])
        first_symptom = candidate["first_symptom"]
        first_root_event = candidate["first_root_event"]
        delay_minutes = float(candidate["delay_minutes"])
        symptom_count = int(candidate["symptom_count"])

        symptom_reason = self._reason(first_symptom) or "<unknown>"
        root_reason = self._reason(first_root_event) or "<unknown>"

        delay_label = f"{delay_minutes:.1f}"

        chain = CausalChain(
            causes=[
                Cause(
                    code="EARLY_AMBIGUOUS_SYMPTOMS",
                    message=(
                        f"Timeline initially showed ambiguous symptom event "
                        f"'{symptom_reason}'"
                    ),
                    role="temporal_context",
                ),
                Cause(
                    code="ROOT_CAUSE_SIGNAL_ARRIVED_LATER",
                    message=(
                        f"Decisive root-cause event '{root_reason}' appeared "
                        f"{delay_label} minutes after the first symptom"
                    ),
                    role="diagnostic_context",
                ),
                Cause(
                    code="DELAYED_ROOT_CAUSE_CONFIRMED",
                    message=(
                        f"Engine selected '{winner_name}' only after the later "
                        "timeline signal made the root cause specific"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="EARLIER_EVENTS_RECLASSIFIED",
                    message=(
                        "Earlier events are retained as symptoms rather than "
                        "the current root cause"
                    ),
                    role="diagnostic_resolution",
                ),
            ]
        )

        evidence = [
            (
                f"First ambiguous symptom '{symptom_reason}' preceded the decisive "
                f"root-cause signal '{root_reason}' by {delay_label} minutes"
            ),
            (
                f"{symptom_count} earlier ambiguous symptom event(s) appeared before "
                f"the root-cause event for '{winner_name}'"
            ),
            f"Final engine winner remains '{winner_name}': {winner_root_cause}",
        ]

        resolution_reason = (
            f"Engine retained '{winner_name}' because the decisive root-cause "
            f"signal appeared {delay_label} minutes after earlier ambiguous symptoms."
        )

        return {
            "root_cause": str(preliminary.get("root_cause", "Unknown")),
            "confidence": float(preliminary.get("confidence", 0.0) or 0.0),
            "causes": chain,
            "evidence": evidence,
            "resolution_patch": {
                "reason": resolution_reason,
                "explained_by": self.name,
                "root_cause_delay_minutes": delay_minutes,
            },
            "delayed_root_cause_detection": {
                "winner": winner_name,
                "winner_root_cause": winner_root_cause,
                "first_symptom_reason": symptom_reason,
                "decisive_root_cause_reason": root_reason,
                "delay_minutes": delay_minutes,
                "earlier_symptom_count": symptom_count,
            },
        }
