import json
from typing import Any

# ----------------------------
# Parsing utilities
# ----------------------------


def load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_pod_phase(pod: dict[str, Any]) -> str:
    return pod.get("status", {}).get("phase", "Unknown")


def get_pod_name(pod: dict[str, Any]) -> str:
    return pod.get("metadata", {}).get("name", "<unknown>")


def normalize_events(events: Any) -> list[dict[str, Any]]:
    if isinstance(events, list):
        # Already a list of event dicts
        return events
    if events.get("kind") == "List":
        return events.get("items", [])
    return [events]


def has_event(events: list[dict[str, Any]], reason: str) -> bool:
    return any(e.get("reason") == reason for e in events)


def pod_condition(pod: dict[str, Any], cond_type: str) -> dict[str, Any] | None:
    for c in pod.get("status", {}).get("conditions", []):
        if c.get("type") == cond_type:
            return c
    return None
