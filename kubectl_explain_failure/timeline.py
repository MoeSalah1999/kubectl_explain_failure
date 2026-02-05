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


class Timeline:
    def __init__(self, events: list[dict[str, Any]]):
        self.events = events

    def first(self, reason: str):
        for e in self.events:
            if e.get("reason") == reason:
                return e
        return None

    def has(self, reason: str) -> bool:
        return any(e.get("reason") == reason for e in self.events)


def build_timeline(events: list[dict[str, Any]]) -> Timeline:
    return Timeline(events)
