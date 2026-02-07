from datetime import datetime, timedelta
from typing import Any


def parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def events_within(events: list[dict[str, Any]], minutes: int) -> list[dict[str, Any]]:
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
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


def build_timeline(events: list[dict[str, Any]]) -> Timeline:
    return Timeline(events)


def timeline_has_pattern(timeline: list[dict[str, Any]], pattern: list[dict[str, str]]) -> bool:
    """
    Checks if a sequence of events in the timeline matches the given pattern.
    Pattern is a list of dicts: [{"kind": "Scheduling", "phase": "Failure"}, ...]
    """
    if not timeline or not pattern:
        return False

    tl_idx = 0
    for p in pattern:
        matched = False
        while tl_idx < len(timeline):
            e = timeline[tl_idx]
            tl_idx += 1
            if all(e.get(k) == v for k, v in p.items()):
                matched = True
                break
        if not matched:
            return False
    return True
