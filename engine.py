from typing import Dict, Any, List, Optional
from rules.base_rule import FailureRule
from model import get_pod_name, get_pod_phase


# ----------------------------
# Heuristic engine
# ----------------------------

def explain_failure(
    pod: Dict[str, Any],
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]],
    rules: List[FailureRule],
    enabled_categories: Optional[List[str]] = None,
    disabled_categories: Optional[List[str]] = None,
    verbose: bool = False,
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
    for rule in rules:
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
