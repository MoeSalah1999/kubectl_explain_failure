import re
from collections.abc import Callable
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

        # handle string or dict
        src = raw.get("source")
        if isinstance(src, dict):
            self.source = src.get("component")
        else:
            self.source = src  # fallback to string or None

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
    def __init__(
        self,
        events: list[dict[str, Any]],
        *,
        relative_to: str = "now",  # "now" | "last_event"
    ):
        self.events = events
        self.normalized = [NormalizedEvent(e) for e in events]
        self.relative_to = relative_to

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
    
    def _reference_time(self) -> datetime:
        """
        Returns the reference time used for window calculations.

        - live mode: current UTC time
        - deterministic mode: timestamp of last event
        """
        if self.relative_to == "now":
            return datetime.now(timezone.utc)

        if self.relative_to == "last_event":
            if not self.events:
                return datetime.now(timezone.utc)

            # Find last event with a timestamp
            for e in reversed(self.events):
                ts = (
                    e.get("eventTime")
                    or e.get("lastTimestamp")
                    or e.get("firstTimestamp")
                    or e.get("timestamp")
                )
                if ts:
                    return parse_time(ts)

            return datetime.now(timezone.utc)

        # Fallback safety
        return datetime.now(timezone.utc)
    
    def events_within_window(
        self,
        minutes: int,
        *,
        reason: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Returns events within the last `minutes` relative to
        the configured timeline reference point.
        """
        reference = self._reference_time()
        cutoff = reference - timedelta(minutes=minutes)

        result = []

        for e in self.events:
            ts = (
                e.get("eventTime")
                or e.get("lastTimestamp")
                or e.get("firstTimestamp")
            )
            if not ts:
                continue

            dt = parse_time(ts)

            if dt >= cutoff and (reason is None or e.get("reason") == reason):
                result.append(e)

        return result

    def duration_between(self, reason_filter: Callable[[dict], bool]) -> float:
        """
        Returns the duration in seconds between the first and last
        event matching the provided filter.

        If fewer than two matching events exist, returns 0.
        """
        matching = [e for e in self.events if reason_filter(e)]

        if len(matching) < 2:
            return 0.0

        # Use eventTime → lastTimestamp → firstTimestamp (consistent with events_within)
        def extract_ts(event: dict[str, Any]) -> str | None:
            return (
                event.get("eventTime")
                or event.get("lastTimestamp")
                or event.get("firstTimestamp")
                or event.get("timestamp")
            )

        first_ts = extract_ts(matching[0])
        last_ts = extract_ts(matching[-1])

        if not first_ts or not last_ts:
            return 0.0

        try:
            start = parse_time(first_ts)
            end = parse_time(last_ts)
            return (end - start).total_seconds()
        except Exception:
            return 0.0

    @property
    def raw_events(self):
        """
        Backwards-compatible view for rules that expect raw event dicts.
        """
        return self.events


def build_timeline(
    events: list[dict[str, Any]],
    *,
    relative_to: str = "now",
) -> Timeline:
    return Timeline(events, relative_to=relative_to)


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


# Structured timeline helpers

def timeline_has_event(
    timeline: "Timeline | list[dict[str, Any]]",
    *,
    kind: str | None = None,
    phase: str | None = None,
    source: str | None = None,
) -> bool:
    """
    Structured event matcher.
    Works with Timeline object or raw event list.
    Avoids fragile string/regex matching.
    """

    if isinstance(timeline, Timeline):
        normalized = timeline.normalized
    else:
        normalized = [NormalizedEvent(e) for e in timeline or []]

    for e in normalized:
        if kind and e.kind != kind:
            continue
        if phase and e.phase != phase:
            continue
        if source and e.source != source:
            continue
        return True

    return False

# ----------------------------
# Temporal stability helper
# ----------------------------

def event_frequency(
    timeline: "Timeline | list[dict[str, Any]]",
    reason: str,
) -> int:
    """
    Count occurrences of a raw event reason.
    Works with Timeline or raw list.
    """

    if isinstance(timeline, Timeline):
        events = timeline.events
    else:
        events = timeline or []

    return sum(1 for e in events if e.get("reason") == reason)