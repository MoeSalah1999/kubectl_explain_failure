import os
from typing import Any

from loader import load_plugins, load_rules
from model import get_pod_name, get_pod_phase
from rules.base_rule import FailureRule

_DEFAULT_RULES = None


def get_default_rules() -> list[FailureRule]:
    global _DEFAULT_RULES
    if _DEFAULT_RULES is None:
        rules_path = os.path.join(os.path.dirname(__file__), "rules")
        plugin_path = os.path.join(os.path.dirname(__file__), "plugins")
        _DEFAULT_RULES = sorted(
            load_rules(rules_path) + load_plugins(plugin_path),
            key=lambda r: getattr(r, "priority", 100),
        )
    return _DEFAULT_RULES


# ----------------------------
# Heuristic engine
# ----------------------------


def explain_failure(
    pod: dict[str, Any],
    events: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
    rules: list[FailureRule] | None = None,
    enabled_categories: list[str] | None = None,
    disabled_categories: list[str] | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """
    Explains why a Pod is failing by evaluating all applicable rules.

    - Aggregates multiple rule matches
    - Picks the rule with highest weighted confidence for root_cause
    - Merges evidence, likely causes, and suggested checks
    - Normalizes confidence using noisy-OR
    - Enforces strong causal precedence for PVC-related failures
    """
    context = context or {}
    rules = rules or get_default_rules()

    pod_name = get_pod_name(pod)
    pod_phase = get_pod_phase(pod)

    explanations: list[tuple[dict[str, Any], FailureRule]] = []

    # ----------------------------
    # Collect container states
    # ----------------------------
    container_states = []
    for c in pod.get("status", {}).get("containerStatuses", []):
        if "state" in c:
            container_states.append(c["state"])
        if "lastState" in c:
            container_states.append(c["lastState"])

    # ----------------------------
    # Rule filtering
    # ----------------------------
    filtered_rules = []
    for rule in rules:
        # Phase gating
        phases = getattr(rule, "phases", None)
        if phases and pod_phase not in phases:
            continue

        # Container-state gating
        required_states = getattr(rule, "container_states", None)
        if required_states:
            if not any(
                s.get("terminated") or s.get("waiting") for s in container_states
            ):
                continue

        filtered_rules.append(rule)

    # ----------------------------
    # Rule evaluation
    # ----------------------------
    for rule in filtered_rules:
        category = getattr(rule, "category", None)

        if enabled_categories and category not in enabled_categories:
            continue
        if disabled_categories and category in disabled_categories:
            continue

        # Dependency enforcement
        dependencies_met = True
        for dep in getattr(rule, "dependencies", []):
            if not any(exp.get("root_cause") == dep for exp, _ in explanations):
                dependencies_met = False
                if verbose:
                    print(
                        f"[DEBUG] Skipping '{rule.name}' "
                        f"(dependency '{dep}' not satisfied)"
                    )
                break
        if not dependencies_met:
            continue

        # Contract enforcement
        requires = getattr(rule, "requires", {})
        if requires.get("pod") and not pod:
            continue

        missing_context = [
            key for key in requires.get("context", []) if key not in context
        ]
        if missing_context:
            if verbose:
                print(
                    f"[DEBUG] Skipping '{rule.name}': "
                    f"missing context {missing_context}"
                )
            continue

        # Rule match
        if rule.matches(pod, events, context):
            exp = rule.explain(pod, events, context)
            explanations.append((exp, rule))
            if verbose:
                print(
                    f"[DEBUG] Rule '{rule.name}' matched "
                    f"(category='{category}', "
                    f"confidence={exp.get('confidence', 0.0):.2f})"
                )

    # ----------------------------
    # No matches → Unknown
    # ----------------------------
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

    # ----------------------------
    # STRONG CAUSAL OVERRIDE: PVC blocks scheduling
    # ----------------------------
    pvc_matches = [
        (exp, rule)
        for exp, rule in explanations
        if getattr(rule, "category", None) == "PersistentVolumeClaim"
    ]

    if pvc_matches:
        best_exp, _ = max(
            pvc_matches,
            key=lambda pair: pair[0].get("confidence", 0.0),
        )

        pvc = context.get("blocking_pvc", {})
        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        # Pending pod with no events → partial certainty
        confidence = best_exp.get("confidence", 0.0)
        if pod_phase == "Pending" and not events:
            confidence = max(confidence, 0.5)

        return {
            "pod": pod_name,
            "phase": pod_phase,
            "root_cause": best_exp.get(
                "root_cause",
                f"Pod is blocked by unbound PersistentVolumeClaim '{pvc_name}'",
            ),
            "confidence": min(1.0, max(confidence, 0.95)),
            "evidence": best_exp.get("evidence", []),
            "likely_causes": best_exp.get("likely_causes", []),
            "suggested_checks": best_exp.get("suggested_checks", []),
        }

    # ----------------------------
    # Weighted root-cause selection
    # ----------------------------
    root_score_map: dict[str, float] = {}

    for exp, rule in explanations:
        root = exp.get("root_cause")
        if not root:
            continue

        score = exp.get("confidence", 0.0) * getattr(rule, "priority", 100)

        required_context = getattr(rule, "requires", {}).get("context", [])
        present_context = sum(1 for c in required_context if c in context)
        if present_context:
            score *= 1.0 + 0.5 * present_context

        root_score_map[root] = max(root_score_map.get(root, 0.0), score)

    best_root_cause = max(
        root_score_map.items(),
        key=lambda item: item[1],
    )[0]

    if verbose:
        print("[DEBUG] Root cause scores:", root_score_map)

    # ----------------------------
    # Noisy-OR confidence aggregation
    # ----------------------------
    combined_confidence = 1.0
    for exp, _ in explanations:
        combined_confidence *= 1.0 - exp.get("confidence", 0.0)
    combined_confidence = 1.0 - combined_confidence

    # ----------------------------
    # Merge explanations
    # ----------------------------
    merged = {
        "pod": pod_name,
        "phase": pod_phase,
        "root_cause": best_root_cause,
        "confidence": combined_confidence,
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
    }

    for exp, _ in explanations:
        merged["evidence"].extend(exp.get("evidence", []))
        merged["likely_causes"].extend(exp.get("likely_causes", []))
        merged["suggested_checks"].extend(exp.get("suggested_checks", []))

    # Deduplicate
    merged["evidence"] = list(dict.fromkeys(merged["evidence"]))
    merged["likely_causes"] = list(dict.fromkeys(merged["likely_causes"]))
    merged["suggested_checks"] = list(dict.fromkeys(merged["suggested_checks"]))

    # Sanity dampening
    if pod_phase == "Pending" and not events:
        merged["confidence"] *= 0.5

    merged["confidence"] = min(1.0, max(0.0, merged["confidence"]))

    return merged
