import re
from datetime import datetime, timedelta, timezone
from typing import Any


def parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def events_within(events: list[dict[str, Any]], minutes: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    result = []

    for e in events:
        ts = e.get("eventTime") or e.get("lastTimestamp") or e.get("firstTimestamp")
        if not ts:
            continue
        if parse_time(ts) >= cutoff:
            result.append(e)

    return result


def repeated_reason(events: list[dict[str, Any]], reason: str, threshold: int) -> bool:
    return sum(1 for e in events if e.get("reason") == reason) >= threshold


class NormalizedEvent:
    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.kind = self._kind()
        self.phase = self._phase()
        self.reason = raw.get("reason")
        self.source = raw.get("source", {}).get("component")

    def _kind(self) -> str:
        reason = (self.raw.get("reason") or "").lower()
        if reason.startswith("failedscheduling"):
            return "Scheduling"
        if "pull" in reason:
            return "Image"
        if "mount" in reason:
            return "Volume"
        return "Generic"

    def _phase(self) -> str:
        reason = (self.raw.get("reason") or "").lower()
        if "fail" in reason or "backoff" in reason:
            return "Failure"
        return "Info"


class Timeline:
    def __init__(self, events: list[dict[str, Any]]):
        self.events = events
        self.normalized = [NormalizedEvent(e) for e in events]

    def first(self, reason: str):
        for e in self.events:
            if e.get("reason") == reason:
                return e
        return None

    def has(self, *, kind: str | None = None, phase: str | None = None) -> bool:
        for e in self.normalized:
            if kind and e.kind != kind:
                continue
            if phase and e.phase != phase:
                continue
            return True
        return False

    def count(self, *, reason: str | None = None) -> int:
        if not reason:
            return len(self.events)
        return sum(1 for e in self.events if e.get("reason") == reason)

    def repeated(self, reason: str, threshold: int) -> bool:
        return self.count(reason=reason) >= threshold

    @property
    def raw_events(self):
        """
        Backwards-compatible view for rules that expect raw event dicts.
        """
        return self.events


def build_timeline(events: list[dict[str, Any]]) -> Timeline:
    return Timeline(events)


def timeline_has_pattern(
    timeline: "Timeline | list[dict[str, Any]]",
    pattern: Any,
) -> bool:
    """
    Supported patterns:
    - string / regex: matches event['reason']
    - list[dict]: structural matching (legacy)
    """

    if isinstance(timeline, Timeline):
        events = timeline.events
    else:
        events = timeline

    if not isinstance(events, list) or not events:
        return False

    # --- SIMPLE STRING / REGEX ---
    if isinstance(pattern, str):
        regex = re.compile(pattern)
        return any(regex.search(e.get("reason", "")) for e in events)

    # --- STRUCTURED SEQUENCE ---
    if not isinstance(pattern, list):
        return False

    idx = 0
    for step in pattern:
        if not isinstance(step, dict):
            return False
        matched = False
        while idx < len(events):
            e = events[idx]
            idx += 1
            if all(e.get(k) == v for k, v in step.items()):
                matched = True
                break
        if not matched:
            return False

    return True
