from datetime import datetime, timedelta
from typing import Any, Dict, List


def parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def events_within(events: List[Dict[str, Any]], minutes: int) -> List[Dict[str, Any]]:
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    result = []

    for e in events:
        ts = e.get("eventTime") or e.get("lastTimestamp") or e.get("firstTimestamp")
        if not ts:
            continue
        if parse_time(ts) >= cutoff:
            result.append(e)

    return result


def repeated_reason(events: List[Dict[str, Any]], reason: str, threshold: int) -> bool:
    return sum(1 for e in events if e.get("reason") == reason) >= threshold
