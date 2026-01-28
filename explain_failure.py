
"""
CLI: kubectl explain-failure --pod POD.json --events EVENTS.json
Purpose: Explain common Kubernetes Pod failures using heuristics.
Scope: Read-only, file-based (no cluster required).
"""

import argparse
import json
from typing import List, Dict, Any

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


def normalize_events(events: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Support both a single Event and a List
    if events.get("kind") == "List":
        return events.get("items", [])
    return [events]


def event_reasons(events: List[Dict[str, Any]]) -> List[str]:
    return [e.get("reason", "") for e in events]


def has_event(events: List[Dict[str, Any]], reason: str) -> bool:
    return any(e.get("reason") == reason for e in events)


# ----------------------------
# Heuristic engine
# ----------------------------

def explain_failure(pod: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    phase = get_pod_phase(pod)
    name = get_pod_name(pod)
    reasons = event_reasons(events)

    explanation = {
        "pod": name,
        "phase": phase,
        "root_cause": "Unknown",
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
    }

    # Pending → FailedScheduling
    if phase == "Pending" and has_event(events, "FailedScheduling"):
        explanation["root_cause"] = "Pod could not be scheduled"
        explanation["evidence"].append("Event: FailedScheduling")
        explanation["likely_causes"].extend([
            "No nodes satisfy resource requests",
            "Node taints or affinity rules prevent scheduling",
            "Cluster autoscaling is disabled or blocked",
        ])
        explanation["suggested_checks"].extend([
            "kubectl describe pod <name>",
            "kubectl get nodes",
            "kubectl get events",
        ])
        return explanation

    # Image pull errors
    if has_event(events, "ImagePullBackOff") or has_event(events, "ErrImagePull"):
        explanation["root_cause"] = "Container image could not be pulled"
        explanation["evidence"].append("Event: ImagePullBackOff / ErrImagePull")
        explanation["likely_causes"].extend([
            "Image name or tag does not exist",
            "Registry authentication failure",
            "Network connectivity issues",
        ])
        explanation["suggested_checks"].extend([
            "kubectl describe pod <name>",
            "Check image name and tag",
            "Verify imagePullSecrets",
        ])
        return explanation

    # CrashLoopBackOff
    if has_event(events, "BackOff"):
        explanation["root_cause"] = "Container is crashing repeatedly"
        explanation["evidence"].append("Event: BackOff")
        explanation["likely_causes"].extend([
            "Application exits with non-zero code",
            "Missing configuration or secrets",
            "Resource limits too low",
        ])
        explanation["suggested_checks"].extend([
            "kubectl logs <pod> --previous",
            "kubectl describe pod <name>",
        ])
        return explanation

    return explanation


# ----------------------------
# Output formatting
# ----------------------------

def print_explanation(result: Dict[str, Any]) -> None:
    print(f"Pod: {result['pod']}")
    print(f"Phase: {result['phase']}")
    print("\nRoot cause:")
    print(f"  {result['root_cause']}")

    if result["evidence"]:
        print("\nEvidence:")
        for e in result["evidence"]:
            print(f"  - {e}")

    if result["likely_causes"]:
        print("\nLikely causes:")
        for c in result["likely_causes"]:
            print(f"  - {c}")

    if result["suggested_checks"]:
        print("\nSuggested checks:")
        for s in result["suggested_checks"]:
            print(f"  - {s}")


# ----------------------------
# CLI
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")
    parser.add_argument("--pod", required=True, help="Path to Pod JSON")
    parser.add_argument("--events", required=True, help="Path to Events JSON")
    args = parser.parse_args()

    pod = load_json(args.pod)
    events_raw = load_json(args.events)
    events = normalize_events(events_raw)

    result = explain_failure(pod, events)
    print_explanation(result)


if __name__ == "__main__":
    main()


