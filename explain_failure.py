
"""
CLI: kubectl explain-failure --pod POD.json --events EVENTS.json
Purpose: Explain common Kubernetes Pod failures using heuristics.
Scalable: Supports dynamic rule loading and cross-object reasoning.
"""

import argparse
import json
import os
import glob
import importlib.util
from typing import List, Dict, Any, Optional
from rules.base_rule import FailureRule

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
    if events.get("kind") == "List":
        return events.get("items", [])
    return [events]

def has_event(events: List[Dict[str, Any]], reason: str) -> bool:
    return any(e.get("reason") == reason for e in events)


# ----------------------------
# Dynamic Rule Loader
# ----------------------------

def load_rules(rule_folder=None) -> List[FailureRule]:
    if rule_folder is None:
        rule_folder = os.path.join(os.path.dirname(__file__), "rules")

    rules: List[FailureRule] = []
    for file in glob.glob(os.path.join(rule_folder, "*.py")):
        if os.path.basename(file) == "base_rule.py":
            continue  # skip the base class

        module_name = os.path.splitext(os.path.basename(file))[0]
        try:
            spec = importlib.util.spec_from_file_location(module_name, file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr in dir(module):
                cls = getattr(module, attr)
                if isinstance(cls, type) and issubclass(cls, FailureRule) and cls is not FailureRule:
                    rules.append(cls())

        except Exception as e:
            print(f"[ERROR] Failed to load rule {file}: {e}")

    return rules


# ----------------------------
# Heuristic engine
# ----------------------------

def explain_failure(pod: Dict[str, Any], events: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--pvc", help="Path to PVC JSON", required=False)
    parser.add_argument("--node", help="Path to Node JSON", required=False)
    parser.add_argument("--pvcs", help="Path to multiple PVC JSONs folder", required=False)
    args = parser.parse_args()

    context = {}
    if args.pvc:
        context["pvc"] = load_json(args.pvc)
    if args.pvcs:
        context["pvcs"] = [load_json(os.path.join(args.pvcs, f)) for f in os.listdir(args.pvcs) if f.endswith(".json")]
    if args.node:
        context["node"] = load_json(args.node)

    pod = load_json(args.pod)
    events_raw = load_json(args.events)
    events = normalize_events(events_raw)

    result = explain_failure(pod, events, context)
    output_result(result, args.format)

# ----------------------------
# Load rules dynamically at runtime
# ----------------------------
RULES = sorted(load_rules(rule_folder=os.path.join(os.path.dirname(__file__), "rules")), key=lambda r: getattr(r, "priority", 100))


if __name__ == "__main__":
    print(f"[INFO] Loaded {len(RULES)} rules:")
    for r in RULES:
        print(f" - {r.name}")
        
    main()
