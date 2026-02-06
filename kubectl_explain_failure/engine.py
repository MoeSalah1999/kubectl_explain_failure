import os
from typing import Any

from kubectl_explain_failure.causality import (
    CausalChain,
    Resolution,
    build_chain,
)
from kubectl_explain_failure.loader import load_plugins, load_rules
from kubectl_explain_failure.model import get_pod_name, get_pod_phase
from kubectl_explain_failure.relations import build_relations
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline

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


def compose_confidence(
    *,
    rule_confidence: float,
    evidence_quality: float = 1.0,
    data_completeness: float = 1.0,
    conflict_penalty: float = 1.0,
) -> float:
    """
    Deterministically compose confidence from independent factors.
    """
    c = rule_confidence
    c *= evidence_quality
    c *= data_completeness
    c *= conflict_penalty
    return min(1.0, max(0.0, c))


def apply_suppressions(
    explanations: list[tuple[dict[str, Any], FailureRule, CausalChain]],
) -> tuple[list[tuple[dict[str, Any], FailureRule, CausalChain]], dict[str, list[str]]]:
    """
    Given a list of matched explanations, automatically suppress rules according to rule.blocks.

    Returns:
    - filtered_explanations: only unsuppressed explanations
    - suppression_map: dict mapping winner rule -> list of suppressed rule names
    """
    winners = []
    suppressed_map: dict[str, list[str]] = {}

    # Track which rules are blocked
    blocked_rules: set[str] = set()
    for exp, rule, chain in sorted(
        explanations, key=lambda e: getattr(e[1], "priority", 100)
    ):
        if rule.name in blocked_rules:
            continue

        # Determine which rules this winner blocks
        blocks = getattr(rule, "blocks", [])
        suppressed_map[rule.name] = []
        for rname in blocks:
            blocked_rules.add(rname)
            suppressed_map[rule.name].append(rname)

        winners.append((exp, rule, chain))

    return winners, suppressed_map


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

    context["relations"] = build_relations(pod, context)
    context["timeline"] = build_timeline(events)

    explanations: list[tuple[dict[str, Any], FailureRule, CausalChain]] = []

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
            if not any(exp.get("root_cause") == dep for exp, _, _ in explanations):
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
            chain = build_chain(exp)
            explanations.append((exp, rule, chain))
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
    # Apply automatic suppression
    # ----------------------------
    filtered_explanations, suppression_map = apply_suppressions(explanations)

    if not filtered_explanations:
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
        (exp, rule, chain)
        for exp, rule, chain in filtered_explanations
        if getattr(rule, "category", None) == "PersistentVolumeClaim"
    ]

    if pvc_matches:
        best_exp, best_rule, best_chain = max(
            pvc_matches, key=lambda pair: pair[0].get("confidence", 0.0)
        )

        pvc = context.get("blocking_pvc", {})
        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        base_conf = best_exp.get("confidence", 0.0)
        evidence_quality = 1.0 if context.get("pvc") else 0.7
        data_completeness = min(1.0, len(context) / 5.0)
        confidence = compose_confidence(
            rule_confidence=base_conf,
            evidence_quality=evidence_quality,
            data_completeness=data_completeness,
            conflict_penalty=1.0,
        )

        confidence = max(confidence, 0.95)

        resolution = Resolution(
            winner=best_rule.name,
            suppressed=[
                r.name for _, r, _ in filtered_explanations if r is not best_rule
            ]
            + suppression_map.get(best_rule.name, []),
            reason="PersistentVolumeClaim is a hard scheduling blocker",
        )

        root_cause_node = best_chain.root()
        result = {
            "pod": pod_name,
            "phase": pod_phase,
            "pvc_name": pvc_name,
            "root_cause": (
                root_cause_node.message
                if root_cause_node is not None
                else best_exp.get("root_cause", "Unknown")
            ),
            "confidence": min(1.0, max(confidence, 0.95)),
            "evidence": best_exp.get("evidence", []),
            "likely_causes": best_exp.get("likely_causes", []),
            "suggested_checks": best_exp.get("suggested_checks", []),
            "resolution": resolution.__dict__,
        }

        if "object_evidence" in best_exp:
            result["object_evidence"] = best_exp["object_evidence"]
        return result

    # ----------------------------
    # Weighted root-cause selection for remaining rules
    # ----------------------------
    root_score_map: dict[str, float] = {}
    for exp, rule, _chain in filtered_explanations:
        root = exp.get("root_cause")
        if not root:
            continue

        score = exp.get("confidence", 0.0) * getattr(rule, "priority", 100)

        required_context = getattr(rule, "requires", {}).get("context", [])
        present_context = sum(1 for c in required_context if c in context)
        if present_context:
            score *= 1.0 + 0.5 * present_context

        root_score_map[root] = max(root_score_map.get(root, 0.0), score)

    best_root_cause = max(root_score_map.items(), key=lambda item: item[1])[0]

    if verbose:
        print("[DEBUG] Root cause scores:", root_score_map)

    # ----------------------------
    # Noisy-OR confidence aggregation
    # ----------------------------
    signal_strength = 1.0
    for exp, _, _ in explanations:
        signal_strength *= 1.0 - exp.get("confidence", 0.0)
    signal_strength = 1.0 - signal_strength

    data_completeness = min(1.0, len(context) / 5.0)
    conflict_penalty = 1.0 - (0.1 * max(0, len(explanations) - 1))

    combined_confidence = signal_strength * data_completeness * conflict_penalty

    # ----------------------------
    # Merge explanations
    # ----------------------------

    # Determine winner for suppression
    winner_rule_name = filtered_explanations[0][1].name
    suppressed_rules = [
        r.name for _, r, _ in filtered_explanations[1:]
    ] + suppression_map.get(winner_rule_name, [])

    merged: dict[str, Any] = {
        "pod": pod_name,
        "phase": pod_phase,
        "root_cause": best_root_cause,
        "confidence": combined_confidence,
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
        "causal_chain": [],
        "resolution": {
            "winner": winner_rule_name,
            "suppressed": suppressed_rules,
            "reason": "Automatic suppression applied based on rule.blocks",
        },
    }

    for exp, _, chain in explanations:
        merged["evidence"].extend(list(exp.get("evidence", [])))
        merged["likely_causes"].extend(list(exp.get("likely_causes", [])))
        merged["suggested_checks"].extend(list(exp.get("suggested_checks", [])))
        for cause in chain.causes:
            merged["causal_chain"].append(cause.message)

        object_evidence = exp.get("object_evidence", {})
        if object_evidence:
            merged.setdefault("object_evidence", {})
            for obj, items in object_evidence.items():
                merged["object_evidence"].setdefault(obj, [])
                merged["object_evidence"][obj].extend(items)

    # Deduplicate
    merged["evidence"] = list(dict.fromkeys(merged["evidence"]))
    merged["likely_causes"] = list(dict.fromkeys(merged["likely_causes"]))
    merged["suggested_checks"] = list(dict.fromkeys(merged["suggested_checks"]))
    merged["causal_chain"] = list(dict.fromkeys(merged["causal_chain"]))

    if "object_evidence" in merged:
        for obj, items in merged["object_evidence"].items():
            merged["object_evidence"][obj] = list(dict.fromkeys(items))

    # Sanity dampening
    if pod_phase == "Pending" and not events:
        merged["confidence"] = float(merged["confidence"]) * 0.5

    merged["confidence"] = min(1.0, max(0.0, merged["confidence"]))

    return merged
