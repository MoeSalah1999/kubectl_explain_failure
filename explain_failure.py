
"""
CLI: kubectl explain-failure --pod POD.json --events EVENTS.json
Purpose: Explain common Kubernetes Pod failures using heuristics.
Scalable: Supports dynamic rule loading and cross-object reasoning.
"""

import argparse
import json
import yaml
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

def normalize_events(events: Any) -> List[Dict[str, Any]]:
    if isinstance(events, list):
        # Already a list of event dicts
        return events
    if events.get("kind") == "List":
        return events.get("items", [])
    return [events]


def has_event(events: List[Dict[str, Any]], reason: str) -> bool:
    return any(e.get("reason") == reason for e in events)


# ----------------------------
# Dynamic Rule Loader
# ----------------------------

class YamlFailureRule(FailureRule):
    def __init__(self, spec: Dict[str, Any]):
        self.name = spec["name"]
        self.category = spec.get("category", "Generic")
        self.severity = spec.get("severity", "Medium")
        self.priority = spec.get("priority", 100)
        self.spec = spec

    def matches(self, pod, events, context) -> bool:
        expr = self.spec["if"]
        # VERY conservative evaluation
        return eval(expr, {}, {
            "pod": pod,
            "events": events,
            "context": context
        })

    def explain(self, pod, events, context):
        return {
            "root_cause": self.spec["then"]["root_cause"],
            "confidence": float(self.spec["then"].get("confidence", 0.5)),
            "evidence": self.spec["then"].get("evidence", []),
            "likely_causes": self.spec["then"].get("likely_causes", []),
            "suggested_checks": self.spec["then"].get("suggested_checks", []),
        }

def build_yaml_rule(spec: Dict[str, Any]) -> FailureRule:
    return YamlFailureRule(spec)


def load_rules(rule_folder=None) -> List[FailureRule]:
    if rule_folder is None:
        rule_folder = os.path.join(os.path.dirname(__file__), "rules")

    rules: List[FailureRule] = []

    # ---- Python rules ----
    for file in glob.glob(os.path.join(rule_folder, "*.py")):
        if os.path.basename(file) == "base_rule.py":
            continue

        module_name = os.path.splitext(os.path.basename(file))[0]
        spec = importlib.util.spec_from_file_location(module_name, file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for attr in dir(module):
            cls = getattr(module, attr)
            if isinstance(cls, type) and issubclass(cls, FailureRule) and cls is not FailureRule:
                rules.append(cls())

    # ---- YAML rules ----
    for yfile in glob.glob(os.path.join(rule_folder, "*.yaml")):
        with open(yfile, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)
            rules.append(build_yaml_rule(spec))

    return rules



# ----------------------------
# Heuristic engine
# ----------------------------

def explain_failure(
    pod: Dict[str, Any],
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    enabled_categories: Optional[List[str]] = None,
    disabled_categories: Optional[List[str]] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Explains why a Pod is failing by evaluating all applicable rules.
    - Aggregates multiple rule matches
    - Picks the rule with highest confidence for root_cause
    - Merges evidence, likely causes, and suggested checks
    - Normalizes confidence using noisy-OR
    """
    context = context or {}

    explanations = []
    pod_phase = get_pod_phase(pod)
    container_states = [c.get("state", {}) for c in pod.get("status", {}).get("containerStatuses", [])]

    filtered_rules = []
    for rule in RULES:
        # Skip rules irrelevant to this pod phase
        applicable_phases = getattr(rule, "phases", None)
        if applicable_phases and pod_phase not in applicable_phases:
            continue

        # Optional: skip rules based on container state
        required_states = getattr(rule, "container_states", None)
        if required_states and not any(s.get("terminated") or s.get("waiting") for s in container_states):
            continue

        filtered_rules.append(rule)

    for rule in filtered_rules:
        cat = getattr(rule, "category", None)
        if enabled_categories and cat not in enabled_categories:
            continue
        if disabled_categories and cat in disabled_categories:
            continue

        # Check rule dependencies
        dependencies_met = True
        for dep_name in getattr(rule, "dependencies", []):
            if not any(e["root_cause"] == dep_name for e in explanations):
                dependencies_met = False
                if verbose:
                    print(f"[DEBUG] Skipping '{rule.name}' because dependency '{dep_name}' not met")
                break
        if not dependencies_met:
            continue

        # Contract enforcement
        req = getattr(rule, "requires", {})

        if req.get("pod") and not pod:
            continue

        if req.get("events") and not events:
            continue

        missing_context = [
            key for key in req.get("context", [])
            if key not in context
        ]

        if missing_context:
            if verbose:
                print(f"[DEBUG] Skipping {rule.name}: missing context {missing_context}")
            continue

        # Evaluate rule
        if rule.matches(pod, events, context):
            exp = rule.explain(pod, events, context)
            explanations.append(exp)
            if verbose:
                print(f"[DEBUG] Rule '{rule.name}' matched (category='{cat}') with confidence {exp.get('confidence', 0.0):.2f}")


    pod_name = get_pod_name(pod)
    pod_phase = get_pod_phase(pod)

    if not explanations:
        return {
            "pod": pod_name,
            "phase": pod_phase,
            "root_cause": "Unknown",
            "evidence": [],
            "likely_causes": [],
            "suggested_checks": [],
            "confidence": 0.0,
        }

    # Pick root_cause from the highest-confidence rule
    best_explanation = max(explanations, key=lambda e: e.get("confidence", 0))

    # Noisy-OR aggregation of confidence from all matching rules
    combined_confidence = 1.0
    for e in explanations:
        combined_confidence *= 1.0 - e.get("confidence", 0.0)
    combined_confidence = 1.0 - combined_confidence  # final combined confidence

    # Merge all evidence, likely_causes, suggested_checks
    merged_explanation = {
        "pod": pod_name,
        "phase": pod_phase,
        "root_cause": best_explanation["root_cause"],
        "confidence": combined_confidence,
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
    }

    for e in explanations:
        merged_explanation["evidence"].extend(e.get("evidence", []))
        merged_explanation["likely_causes"].extend(e.get("likely_causes", []))
        merged_explanation["suggested_checks"].extend(e.get("suggested_checks", []))

    # Remove duplicates for cleaner output
    merged_explanation["evidence"] = list(dict.fromkeys(merged_explanation["evidence"]))
    merged_explanation["likely_causes"] = list(dict.fromkeys(merged_explanation["likely_causes"]))
    merged_explanation["suggested_checks"] = list(dict.fromkeys(merged_explanation["suggested_checks"]))

    # Sanity check: reduce confidence for Pending Pods with no events
    if pod_phase == "Pending" and not events:
        merged_explanation["confidence"] *= 0.5

    # Clamp confidence to [0.0, 1.0]
    merged_explanation["confidence"] = min(1.0, max(0.0, merged_explanation["confidence"]))

    return merged_explanation


# ----------------------------
# Output formatting
# ----------------------------

def output_result(result: Dict[str, Any], fmt: str) -> None:
    """
    Nicely prints the Pod failure explanation.
    - Shows root_cause from the highest-confidence rule
    - Displays merged evidence, likely causes, suggested checks
    - Sorts items alphabetically for deterministic output
    """
    if fmt == "json":
        print(json.dumps(result, indent=2))
        return

    print(f"Pod: {result['pod']}")
    print(f"Phase: {result['phase']}")
    print(f"\nRoot cause:\n  {result['root_cause']}")
    print(f"\nConfidence: {int(result['confidence'] * 100)}%")

    # Alphabetically sort lists for cleaner deterministic output
    for key in ("evidence", "likely_causes", "suggested_checks"):
        items = sorted(result[key])
        if items:
            print(f"\n{key.replace('_', ' ').title()}:")
            for item in items:
                print(f"  - {item}")


# ----------------------------
# CLI
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")
    parser.add_argument("--pod", required=True, help="Path to Pod JSON")
    parser.add_argument("--events", required=True, help="Path to Events JSON")
    parser.add_argument(
        "--format",
        choices=["text", "json", "yaml"],
        default="text",
        help="Output format (text, json, yaml)"
    )
    parser.add_argument("--pvc", help="Path to PVC JSON", required=False)
    parser.add_argument("--node", help="Path to Node JSON", required=False)
    parser.add_argument("--pvcs", help="Path to multiple PVC JSONs folder", required=False)
    parser.add_argument("--service", help="Path to Service JSON", required=False)
    parser.add_argument("--endpoints", help="Path to Endpoints JSON", required=False)
    parser.add_argument("--statefulsets", help="Folder of StatefulSet JSONs", required=False)
    parser.add_argument("--daemonsets", help="Folder of DaemonSet JSONs", required=False)
    parser.add_argument(
        "--enable-categories",
        nargs="*",
        default=None,
        help="Only evaluate rules in these categories"
    )
    parser.add_argument(
        "--disable-categories",
        nargs="*",
        default=None,
        help="Skip rules in these categories"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log evaluated rules and their confidence"
    )

    args = parser.parse_args()

    context = {}
    if args.pvc:
        context["pvc"] = load_json(args.pvc)
    if args.pvcs:
        context["pvcs"] = [load_json(os.path.join(args.pvcs, f)) for f in os.listdir(args.pvcs) if f.endswith(".json")]
    if args.node:
        context["node"] = load_json(args.node)
    if args.service:
        context["svc"] = load_json(args.service)
    if args.endpoints:
        context["ep"] = load_json(args.endpoints)
    if args.statefulsets:
        context["sts"] = [load_json(os.path.join(args.statefulsets, f)) for f in os.listdir(args.statefulsets) if f.endswith(".json")]
    if args.daemonsets:
        context["ds"] = [load_json(os.path.join(args.daemonsets, f)) for f in os.listdir(args.daemonsets) if f.endswith(".json")]


    pod = load_json(args.pod)
    events_raw = load_json(args.events)
    events = normalize_events(events_raw)

    result = explain_failure(
        pod,
        events,
        context,
        enabled_categories=args.enable_categories,
        disabled_categories=args.disable_categories,
        verbose=args.verbose
    )

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
