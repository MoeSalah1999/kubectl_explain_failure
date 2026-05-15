from __future__ import annotations

from collections import Counter
from typing import Any, cast

from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SecondaryFailureMaskedByPrimaryRule(FailureRule):
    """
    Explains when a lower-level matched failure signal is real, but should be
    read as secondary because the engine already selected a stronger primary
    blocker.

    This is intentionally post-resolution:
    - it uses the winner and suppressed matched rules chosen by the engine
    - it inspects the recent timeline window instead of raw event existence
    - it preserves the primary root cause and adds diagnostic context
    """

    name = "SecondaryFailureMaskedByPrimary"
    category = "Compound"
    priority = 7
    deterministic = True
    post_resolution = True
    augment_only = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 30
    CACHE_KEY = "_secondary_failure_masked_by_primary_candidate"

    DOMAIN_ORDER = {
        "Admission": 10,
        "PersistentVolumeClaim": 20,
        "Storage": 25,
        "Scheduling": 30,
        "Node": 35,
        "Networking": 40,
        "Image": 50,
        "Container": 60,
        "Probes": 70,
    }

    ACTIONABLE_DOMAINS = set(DOMAIN_ORDER)
    NON_ACTIONABLE_RULES = {
        "LowConfidenceDiagnosis",
        "MultipleIndependentFailures",
        "RootCauseAmbiguity",
        "SecondaryFailureMaskedByPrimary",
        "SuppressedSignalExplanation",
    }

    def _domain_for(self, item: dict[str, Any]) -> str:
        category = str(item.get("category", "") or "").strip()
        if category and category != "Compound":
            return category

        text = " ".join(
            [
                str(item.get("name", "")),
                str(item.get("root_cause", "")),
            ]
        ).lower()

        markers = (
            ("pvc", "PersistentVolumeClaim"),
            ("volume", "Storage"),
            ("mount", "Storage"),
            ("schedul", "Scheduling"),
            ("image", "Image"),
            ("pull", "Image"),
            ("node", "Node"),
            ("network", "Networking"),
            ("probe", "Probes"),
            ("crash", "Container"),
            ("container", "Container"),
            ("admission", "Admission"),
            ("webhook", "Admission"),
        )
        for marker, domain in markers:
            if marker in text:
                return domain
        return category

    def _recent_reasons(self, timeline: Timeline) -> list[str]:
        counts = Counter(
            str(event.get("reason", "")).strip()
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")).strip()
        )
        return [reason for reason, _ in counts.most_common(5)]

    def _recent_failure_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")).strip()
        ]

    def _candidate(self, context: dict[str, Any]) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        engine_state = context.get("_engine_state", {}) or {}
        preliminary = engine_state.get("preliminary_result") or {}
        resolution = preliminary.get("resolution") or {}
        winner_match = engine_state.get("winner_match")
        suppressed = engine_state.get("suppressed_matched_rules", []) or []

        if not isinstance(winner_match, dict) or not suppressed:
            return None

        winner_name = str(resolution.get("winner", "")).strip()
        if not winner_name:
            return None

        winner_domain = self._domain_for(winner_match)
        winner_order = self.DOMAIN_ORDER.get(winner_domain)
        if winner_order is None:
            return None

        recent_events = self._recent_failure_events(timeline)
        if not recent_events:
            return None

        secondary: list[dict[str, Any]] = []
        for item in suppressed:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            if not name or name in self.NON_ACTIONABLE_RULES:
                continue

            domain = self._domain_for(item)
            domain_order = self.DOMAIN_ORDER.get(domain)
            if domain_order is None or domain not in self.ACTIONABLE_DOMAINS:
                continue

            if domain_order < winner_order:
                continue

            secondary.append(
                {
                    **item,
                    "domain": domain,
                    "domain_order": domain_order,
                }
            )

        if not secondary:
            return None

        secondary = sorted(
            secondary,
            key=lambda item: (
                int(item.get("domain_order", 0)),
                str(item.get("name", "")),
            ),
        )

        return {
            "preliminary": preliminary,
            "winner_name": winner_name,
            "winner_match": winner_match,
            "winner_domain": winner_domain,
            "secondary": secondary,
            "recent_reasons": self._recent_reasons(timeline),
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
                "SecondaryFailureMaskedByPrimary explain() called without match"
            )

        preliminary = cast(dict[str, Any], candidate["preliminary"])
        winner_name = str(candidate["winner_name"])
        winner_match = cast(dict[str, Any], candidate["winner_match"])
        winner_domain = str(candidate["winner_domain"])
        secondary = cast(list[dict[str, Any]], candidate["secondary"])
        recent_reasons = cast(list[str], candidate["recent_reasons"])

        secondary_details = [
            {
                "name": str(item.get("name", "")),
                "category": str(item.get("category", "") or ""),
                "domain": str(item.get("domain", "")),
                "root_cause": str(item.get("root_cause", "") or ""),
                "confidence": float(item.get("confidence", 0.0) or 0.0),
            }
            for item in secondary
        ]
        secondary_names: list[str] = [str(item["name"]) for item in secondary_details]

        resolution_reason = (
            f"Engine kept '{winner_name}' as the primary diagnosis and marked "
            f"{', '.join(secondary_names)} as secondary because the winning "
            f"{winner_domain} signal gates or explains the later failure stage."
        )

        evidence = [
            (
                f"Primary engine winner '{winner_name}' masked secondary matched "
                f"signal(s): {', '.join(secondary_names)}"
            ),
            (
                f"Winner domain '{winner_domain}' has startup precedence over "
                "the suppressed secondary failure domain(s)"
            ),
        ]
        if recent_reasons:
            evidence.append(
                "Recent timeline window contains the overlapping failure signal(s): "
                f"{', '.join(recent_reasons)}"
            )

        return {
            "root_cause": str(preliminary.get("root_cause", "Unknown")),
            "confidence": float(preliminary.get("confidence", 0.0) or 0.0),
            "evidence": evidence,
            "resolution_patch": {
                "reason": resolution_reason,
                "explained_by": self.name,
                "primary_domain": winner_domain,
                "primary_confidence": float(
                    winner_match.get("confidence", preliminary.get("confidence", 0.0))
                    or 0.0
                ),
                "masked_secondary_failures": secondary_details,
            },
            "secondary_failure_masking": {
                "primary": winner_name,
                "primary_domain": winner_domain,
                "secondary": secondary_details,
                "recent_event_reasons": recent_reasons,
            },
        }
