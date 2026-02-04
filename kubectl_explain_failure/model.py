import json
from typing import Any, Dict, List

# ----------------------------
# Parsing utilities
# ----------------------------


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_pod_phase(pod: Dict[str, Any]) -> str:
    return pod.get("status", {}).get("phase", "Unknown")


def get_pod_name(pod: Dict[str, Any]) -> str:
    return pod.get("metadata", {}).get("name", "<unknown>")


def normalize_events(events: Any) -> List[Dict[str, Any]]:
    if isinstance(events, list):
        # Already a list of event dicts
        return events
    if events.get("kind") == "List":
        return events.get("items", [])
    return [events]


def has_event(events: List[Dict[str, Any]], reason: str) -> bool:
    return any(e.get("reason") == reason for e in events)
