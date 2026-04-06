from __future__ import annotations

from collections import Counter

from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SuppressedSignalExplanationRule(FailureRule):
    """
    Adds an explicit explanation when the engine deliberately suppresses
    lower-level matched signals in favor of a more specific winner.

    This is a post-resolution engine rule:
    - it inspects the actual winner and the real matched rules that were
      suppressed after rule.blocks resolution
    - it only enriches results when multiple matched signals were
      intentionally suppressed in the same recent incident window
    - it preserves the original winner/root cause and explains the
      resolution decision instead of replacing it
    """

    name = "SuppressedSignalExplanation"
    category = "Resolution"
    priority = 6
    deterministic = True
    post_resolution = True
    augment_only = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 20
    CACHE_KEY = "_suppressed_signal_explanation_candidate"

    def _recent_reasons(self, timeline: Timeline) -> list[str]:
        recent_events = timeline.events_within_window(self.WINDOW_MINUTES)
        counts = Counter(
            str(event.get("reason", "")).strip()
            for event in recent_events
            if str(event.get("reason", "")).strip()
        )
        return [reason for reason, _ in counts.most_common(3)]

    def _candidate(self, context: dict) -> dict | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        engine_state = context.get("_engine_state", {}) or {}
        preliminary = engine_state.get("preliminary_result") or {}
        resolution = preliminary.get("resolution") or {}
        winner_name = str(resolution.get("winner", "")).strip()
        if not winner_name:
            return None

        winner_match = engine_state.get("winner_match")
        suppressed_matched = engine_state.get("suppressed_matched_rules", []) or []
        if winner_match is None or len(suppressed_matched) < 2:
            return None

        recent_reasons = self._recent_reasons(timeline)
        if not recent_reasons:
            return None

        categories = {
            str(item.get("category", "")).strip()
            for item in suppressed_matched
            if str(item.get("category", "")).strip()
        }
        winner_category = str(winner_match.get("category", "")).strip()
        if (
            len(categories) < 2
            and winner_category in categories
            and len(suppressed_matched) < 3
        ):
            return None

        return {
            "preliminary": preliminary,
            "winner_name": winner_name,
            "winner_match": winner_match,
            "suppressed_matched": suppressed_matched,
            "recent_reasons": recent_reasons,
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
            raise ValueError(
                "SuppressedSignalExplanation explain() called without match"
            )

        preliminary = candidate["preliminary"]
        winner_name = candidate["winner_name"]
        winner_match = candidate["winner_match"]
        suppressed_matched = candidate["suppressed_matched"]
        recent_reasons = candidate["recent_reasons"]

        suppressed_names = sorted(
            {
                str(item.get("name", "")).strip()
                for item in suppressed_matched
                if str(item.get("name", "")).strip()
            }
        )
        winner_root_cause = str(preliminary.get("root_cause", "Unknown"))
        winner_category = str(winner_match.get("category", "") or "")

        suppressed_details = sorted(
            [
                {
                    "name": str(item.get("name", "")),
                    "category": str(item.get("category", "") or ""),
                    "root_cause": str(item.get("root_cause", "") or ""),
                    "confidence": float(item.get("confidence", 0.0) or 0.0),
                }
                for item in suppressed_matched
                if str(item.get("name", "")).strip()
            ],
            key=lambda item: str(item.get("name", "")),
        )

        resolution_reason = (
            f"Engine kept '{winner_name}' as the primary diagnosis because it is the "
            f"most specific matched signal in the recent incident window and "
            f"suppressed {len(suppressed_names)} secondary signal(s): "
            f"{', '.join(suppressed_names)}"
        )

        return {
            "root_cause": winner_root_cause,
            "confidence": float(preliminary.get("confidence", 0.0) or 0.0),
            "evidence": [
                (
                    f"Engine suppressed {len(suppressed_names)} secondary matched "
                    f"signal(s): {', '.join(suppressed_names)}"
                ),
                (
                    "Recent timeline still shows overlapping failure reasons in the "
                    f"same incident window: {', '.join(recent_reasons)}"
                ),
            ],
            "resolution_patch": {
                "reason": resolution_reason,
                "explained_by": self.name,
                "suppressed_details": suppressed_details,
                "winner_category": winner_category,
            },
            "suppressed_signal_explanation": {
                "winner": winner_name,
                "winner_root_cause": winner_root_cause,
                "suppressed": suppressed_names,
                "recent_event_reasons": recent_reasons,
            },
        }
