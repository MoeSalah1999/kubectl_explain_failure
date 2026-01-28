
"""
CLI: kubectl explain-failure --pod POD.json --events EVENTS.json
Purpose: Explain common Kubernetes Pod failures using heuristics.
Scope: Read-only, file-based (no cluster required).
"""

import argparse
import json
from typing import List, Dict, Any, Callable, Optional

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
# Rule engine
# ----------------------------

class FailureRule:
    name: str

    def matches(
        self,
        pod: Dict[str, Any],
        events: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> bool:
        raise NotImplementedError

    def explain(
        self,
        pod: Dict[str, Any],
        events: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        raise NotImplementedError


# ----------------------------
# Rules
# ----------------------------

class FailedSchedulingRule(FailureRule):
    name = "FailedScheduling"

    def matches(self, pod, events, context) -> bool:
        return (
            get_pod_phase(pod) == "Pending"
            and has_event(events, "FailedScheduling")
        )

    def explain(self, pod, events, context) -> Dict[str, Any]:
        return {
            "root_cause": "Pod could not be scheduled",
            "evidence": ["Event: FailedScheduling"],
            "likely_causes": [
                "No nodes satisfy resource requests",
                "Node taints or affinity rules prevent scheduling",
                "Cluster autoscaling is disabled or blocked",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get nodes",
                "kubectl get events",
            ],
            "confidence": 0.90,
        }


class ImagePullRule(FailureRule):
    name = "ImagePullError"

    def matches(self, pod, events, context) -> bool:
        return (
            has_event(events, "ImagePullBackOff")
            or has_event(events, "ErrImagePull")
        )

    def explain(self, pod, events, context) -> Dict[str, Any]:
        return {
            "root_cause": "Container image could not be pulled",
            "evidence": ["Event: ImagePullBackOff / ErrImagePull"],
            "likely_causes": [
                "Image name or tag does not exist",
                "Registry authentication failure",
                "Network connectivity issues",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "Check image name and tag",
                "Verify imagePullSecrets",
            ],
            "confidence": 0.95,
        }


class CrashLoopRule(FailureRule):
    name = "CrashLoopBackOff"

    def matches(self, pod, events, context) -> bool:
        return has_event(events, "BackOff")

    def explain(self, pod, events, context) -> Dict[str, Any]:
        return {
            "root_cause": "Container is crashing repeatedly",
            "evidence": ["Event: BackOff"],
            "likely_causes": [
                "Application exits with non-zero code",
                "Missing configuration or secrets",
                "Resource limits too low",
            ],
            "suggested_checks": [
                "kubectl logs <pod> --previous",
                "kubectl describe pod <name>",
            ],
            "confidence": 0.85,
        }

class OOMKilledRule(FailureRule):
    name = "OOMKilled"

    def matches(self, pod, events, context) -> bool:
        containers = pod.get("status", {}).get("containerStatuses", [])
        return any(
            c.get("lastState", {}).get("terminated", {}).get("reason") == "OOMKilled"
            for c in containers
        )

    def explain(self, pod, events, context) -> Dict[str, Any]:
        return {
            "root_cause": "Container was killed due to out-of-memory",
            "evidence": ["Container state: OOMKilled"],
            "likely_causes": [
                "Memory limit too low",
                "Memory leak in application",
            ],
            "suggested_checks": [
                "Review container memory limits",
                "Inspect application memory usage",
            ],
            "confidence": 0.95,
        }


class FailedMountRule(FailureRule):
    name = "FailedMount"

    def matches(self, pod, events, context) -> bool:
        return has_event(events, "FailedMount")

    def explain(self, pod, events, context) -> Dict[str, Any]:
        return {
            "root_cause": "Volume could not be mounted",
            "evidence": ["Event: FailedMount"],
            "likely_causes": [
                "PersistentVolumeClaim not bound",
                "Storage backend unavailable",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl get pvc",
            ],
            "confidence": 0.85,
        }


RULES: List[FailureRule] = [
    FailedSchedulingRule(),
    ImagePullRule(),
    CrashLoopRule(),
    OOMKilledRule(),
    FailedMountRule(),
]

# ----------------------------
# Heuristic engine
# ----------------------------

def explain_failure(
    pod: Dict[str, Any],
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    context = context or {}

    result = {
        "pod": get_pod_name(pod),
        "phase": get_pod_phase(pod),
        "root_cause": "Unknown",
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
        "confidence": 0.0,
    }

    for rule in RULES:
        if rule.matches(pod, events, context):
            result.update(rule.explain(pod, events, context))
            return result

    return result



# ----------------------------
# Output formatting
# ----------------------------

def output_result(result: Dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result, indent=2))
        return

    print(f"Pod: {result['pod']}")
    print(f"Phase: {result['phase']}")
    print(f"\nRoot cause:\n  {result['root_cause']}")
    print(f"\nConfidence: {int(result['confidence'] * 100)}%")

    for key in ("evidence", "likely_causes", "suggested_checks"):
        if result[key]:
            print(f"\n{key.replace('_', ' ').title()}:")
            for item in result[key]:
                print(f"  - {item}")



# ----------------------------
# CLI
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")
    parser.add_argument("--pod", required=True, help="Path to Pod JSON")
    parser.add_argument("--events", required=True, help="Path to Events JSON")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format",)
    parser.add_argument("--pvc", help="Path to PVC JSON", required=False)
    parser.add_argument("--node", help="Path to Node JSON", required=False)
    args = parser.parse_args()

    context={}
    if args.pvc:
        context["pvc"] = load_json(args.pvc)
    if args.node:
        context["node"] = load_json(args.node)
    
    pod = load_json(args.pod)
    events_raw = load_json(args.events)
    events = normalize_events(events_raw)

    result = explain_failure(pod, events, context)
    output_result(result, args.format)


if __name__ == "__main__":
    main()


