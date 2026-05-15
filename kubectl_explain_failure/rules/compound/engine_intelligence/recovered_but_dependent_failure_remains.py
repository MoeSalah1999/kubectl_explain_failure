from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class RecoveredButDependentFailureRemainsRule(FailureRule):
    """
    Explains when an earlier platform or dependency blocker has recovered, but
    the workload still has an active dependent failure.

    Real-world behavior:
    - pods often retain historical events from an earlier storage, scheduling,
      node, or dependency outage after that blocker has recovered
    - kubelet then continues to emit readiness, liveness, backoff, or runtime
      failure events because the workload still cannot satisfy its own health
      contract
    - this rule runs after engine resolution and annotates the active winner so
      operators do not chase a recovered precursor while a dependent failure
      still blocks service readiness
    """

    name = "RecoveredButDependentFailureRemains"
    category = "Compound"
    priority = 7
    deterministic = True
    post_resolution = True
    augment_only = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 60
    CACHE_KEY = "_recovered_but_dependent_failure_remains_candidate"

    DEPENDENT_WINNER_DOMAINS = {
        "Container",
        "Probes",
        "Image",
        "Networking",
    }

    RECOVERY_REASON_DOMAINS = {
        "ProvisioningSucceeded": "Storage",
        "VolumeBound": "Storage",
        "SuccessfulAttachVolume": "Storage",
        "SuccessfulMountVolume": "Storage",
        "NodeReady": "Node",
        "DependencyRecovered": "Dependency",
        "DependencyAvailable": "Dependency",
        "EndpointsReady": "Networking",
    }

    RECOVERY_MESSAGE_MARKERS = (
        "successfully provisioned",
        "successfully assigned",
        "successfully mounted",
        "successfully attached",
        "became ready",
        "dependency recovered",
        "dependency available",
        "endpoints ready",
        "service endpoints are ready",
        "connection restored",
    )

    DEPENDENT_FAILURE_REASONS = {
        "Unhealthy",
        "BackOff",
        "CrashLoopBackOff",
        "Killing",
        "Failed",
        "Error",
    }

    DEPENDENT_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "dependency",
        "connection refused",
        "timed out",
        "timeout",
        "back-off",
        "crashloopbackoff",
    )

    DOMAIN_MARKERS = (
        ("probe", "Probes"),
        ("readiness", "Probes"),
        ("liveness", "Probes"),
        ("startup", "Probes"),
        ("image", "Image"),
        ("pull", "Image"),
        ("network", "Networking"),
        ("dns", "Networking"),
        ("container", "Container"),
        ("crash", "Container"),
        ("runtime", "Container"),
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

    def _domain_for_match(self, item: dict[str, Any]) -> str:
        category = str(item.get("category", "") or "").strip()
        if category and category != "Compound":
            return category

        text = " ".join(
            [
                str(item.get("name", "")),
                str(item.get("root_cause", "")),
            ]
        ).lower()
        for marker, domain in self.DOMAIN_MARKERS:
            if marker in text:
                return domain
        return category

    def _recovery_domain(self, event: dict[str, Any]) -> str | None:
        reason = str(event.get("reason", "") or "").strip()
        if reason in self.RECOVERY_REASON_DOMAINS:
            return self.RECOVERY_REASON_DOMAINS[reason]

        message = str(event.get("message", "") or "").lower()
        if any(marker in message for marker in self.RECOVERY_MESSAGE_MARKERS):
            if "volume" in message or "provision" in message or "mount" in message:
                return "Storage"
            if "assign" in message or "schedul" in message:
                return "Scheduling"
            if "node" in message or "kubelet" in message:
                return "Node"
            if "endpoint" in message or "connection" in message:
                return "Networking"
            return "Dependency"

        return None

    def _is_dependent_failure_event(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason", "") or "").strip()
        message = str(event.get("message", "") or "").lower()
        if reason in self.DEPENDENT_FAILURE_REASONS:
            return True
        return any(marker in message for marker in self.DEPENDENT_FAILURE_MARKERS)

    def _recent_reasons(self, events: list[dict[str, Any]]) -> list[str]:
        counts = Counter(
            str(event.get("reason", "")).strip()
            for event in events
            if str(event.get("reason", "")).strip()
        )
        return [reason for reason, _ in counts.most_common(5)]

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        engine_state = context.get("_engine_state", {}) or {}
        preliminary = engine_state.get("preliminary_result") or {}
        winner_match = engine_state.get("winner_match")
        if not isinstance(preliminary, dict) or not isinstance(winner_match, dict):
            return None

        winner_name = str(
            (preliminary.get("resolution") or {}).get("winner", "")
        ).strip()
        if not winner_name:
            return None

        winner_domain = self._domain_for_match(winner_match)
        if winner_domain not in self.DEPENDENT_WINNER_DOMAINS:
            return None

        if not bool(preliminary.get("blocking", False)):
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        dependent_still_active = any(
            not bool(status.get("ready", True))
            or bool((status.get("state", {}) or {}).get("waiting"))
            for status in statuses
        )
        if not dependent_still_active:
            return None

        ordered = self._ordered_recent_events(timeline)
        if len(ordered) < 2:
            return None

        recovery: dict[str, Any] | None = None
        recovery_domain = ""
        failure: dict[str, Any] | None = None

        for event in ordered:
            domain = self._recovery_domain(event)
            if domain is not None:
                recovery = event
                recovery_domain = domain
                failure = None
                continue

            if recovery is not None and self._is_dependent_failure_event(event):
                failure = event

        if recovery is None or failure is None:
            return None

        recovery_time = self._event_time(recovery)
        failure_time = self._event_time(failure)
        if recovery_time is not None and failure_time is not None:
            if recovery_time >= failure_time:
                return None

        return {
            "preliminary": preliminary,
            "winner_name": winner_name,
            "winner_match": winner_match,
            "winner_domain": winner_domain,
            "recovery": recovery,
            "recovery_domain": recovery_domain,
            "failure": failure,
            "recent_reasons": self._recent_reasons(ordered),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError(
                "RecoveredButDependentFailureRemains explain() called without match"
            )

        preliminary = candidate["preliminary"]
        winner_name = str(candidate["winner_name"])
        winner_domain = str(candidate["winner_domain"])
        recovery = candidate["recovery"]
        recovery_domain = str(candidate["recovery_domain"])
        failure = candidate["failure"]
        recent_reasons = candidate["recent_reasons"]

        recovery_reason = str(recovery.get("reason", "") or "<unknown>")
        recovery_message = str(recovery.get("message", "") or "")
        failure_reason = str(failure.get("reason", "") or "<unknown>")
        failure_message = str(failure.get("message", "") or "")

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPENDENCY_RECOVERY_OBSERVED",
                    message=(
                        f"Timeline shows {recovery_domain} recovery signal "
                        f"'{recovery_reason}' before the current failure"
                    ),
                    role="dependency_context",
                ),
                Cause(
                    code="DEPENDENT_FAILURE_REMAINS_ACTIVE",
                    message=(
                        f"Active diagnosis '{winner_name}' remains after the "
                        "dependency or platform recovery"
                    ),
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="RECOVERED_SIGNAL_NOT_CURRENT_ROOT",
                    message=(
                        "The recovered precursor should be treated as context, "
                        "not as the current blocking root cause"
                    ),
                    role="diagnostic_resolution",
                ),
                Cause(
                    code="WORKLOAD_STILL_NOT_READY",
                    message=(
                        "The workload remains degraded because the dependent "
                        "health or runtime failure continues"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Recovered {recovery_domain} signal '{recovery_reason}' appears "
                "before the active dependent failure"
            ),
            (
                f"Active engine winner '{winner_name}' is still in dependent "
                f"domain '{winner_domain}'"
            ),
            f"Later dependent failure signal remains present: {failure_reason}",
        ]
        if recent_reasons:
            evidence.append(
                "Recent timeline contains recovery followed by failure reasons: "
                f"{', '.join(recent_reasons)}"
            )

        resolution_reason = (
            f"Engine kept '{winner_name}' as the active diagnosis because the "
            f"earlier {recovery_domain} signal recovered before the dependent "
            "failure continued."
        )

        return {
            "root_cause": str(preliminary.get("root_cause", "Unknown")),
            "confidence": float(preliminary.get("confidence", 0.0) or 0.0),
            "causes": chain,
            "evidence": evidence,
            "resolution_patch": {
                "reason": resolution_reason,
                "explained_by": self.name,
                "recovered_domain": recovery_domain,
                "dependent_failure_domain": winner_domain,
            },
            "recovered_but_dependent_failure_remains": {
                "winner": winner_name,
                "recovered_domain": recovery_domain,
                "dependent_failure_domain": winner_domain,
                "recovery": {
                    "reason": recovery_reason,
                    "message": recovery_message,
                },
                "remaining_failure": {
                    "reason": failure_reason,
                    "message": failure_message,
                },
                "recent_event_reasons": recent_reasons,
            },
        }
