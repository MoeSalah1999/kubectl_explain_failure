import os
from typing import Dict, Any, List, Optional
from rules.base_rule import FailureRule
from loader import load_rules, load_plugins
from model import get_pod_name, get_pod_phase


_DEFAULT_RULES = None

def get_default_rules() -> List[FailureRule]:
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
    pod: Dict[str, Any],
    events: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    rules: Optional[List[FailureRule]] = None,
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

    # -------------------------------------------------
    # PVC inference from Pod spec (last-resort signal)
    # -------------------------------------------------
    # Some execution paths do not load PVC objects at all.
    # If the Pod references a PVC, we must still satisfy
    # rule contracts to allow PVC rules to evaluate.
    if "pvc" not in context:
        volumes = pod.get("spec", {}).get("volumes", [])
        for v in volumes:
            pvc_ref = v.get("persistentVolumeClaim")
            if pvc_ref and pvc_ref.get("claimName"):
                # Synthetic PVC placeholder (object may be missing)
                context["pvc"] = {
                    "metadata": {
                        "name": pvc_ref["claimName"]
                    },
                    "status": {
                        "phase": "Unknown"
                    }
                }
                # Do NOT break earlier context if present
                break

    if rules is None:
        rules = get_default_rules()

    explanations = []
    pod_phase = get_pod_phase(pod)
    container_states = []
    for c in pod.get("status", {}).get("containerStatuses", []):
        if "state" in c:
            container_states.append(c["state"])
        if "lastState" in c:
            container_states.append(c["lastState"])

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
            if not any(exp.get("root_cause") == dep_name for exp, _ in explanations):
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
            explanations.append((exp, rule))
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
    
    # ----------------------------
    # EARLY CAUSAL OVERRIDE: PVC blocks scheduling
    # ----------------------------
    if context.get("pvc_unbound"):
        for exp, rule in explanations:
            root = exp.get("root_cause", "").lower()

            # Override generic scheduling causes when PVC is unbound
            if (
                "scheduled" in root
                or "scheduling" in root
                or "unschedulable" in root
            ):
                pvc = context.get("blocking_pvc", {})
                pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

                return {
                    "pod": pod_name,
                    "phase": pod_phase,
                    "root_cause": f"Pod is blocked by unbound PersistentVolumeClaim '{pvc_name}'",
                    "confidence": max(exp.get("confidence", 0.0), 0.95),
                    "evidence": [
                        f"PersistentVolumeClaim '{pvc_name}' is not bound",
                        "Pod remains Pending due to storage dependency",
                    ],
                    "likely_causes": [
                        "No PersistentVolume is available for the claim",
                        "StorageClass provisioning failed",
                        "Access modes or capacity mismatch",
                    ],
                    "suggested_checks": [
                        "kubectl describe pvc <name>",
                        "kubectl get pv",
                        "kubectl describe storageclass",
                    ],
                }


    # ----------------------------
    # Weighted root_cause selection (PVC-prioritized)
    # ----------------------------

    # explanations now contains (exp, rule) tuples
    eval_list = explanations

    # If any PVC rules matched, ONLY consider them
    pvc_eval = [
        (exp, rule)
        for exp, rule in eval_list
        if getattr(rule, "category", None) == "PersistentVolumeClaim"
    ]

    if pvc_eval:
        eval_list = pvc_eval

    root_score_map = {}

    for exp, rule in eval_list:
        if not exp.get("root_cause"):
            continue

        # Base score
        score = exp.get("confidence", 0.0) * getattr(rule, "priority", 100)

        # Context boost
        required_context = getattr(rule, "requires", {}).get("context", [])
        present_context = sum(1 for ctx in required_context if ctx in context)
        if present_context:
            score *= 1.0 + 0.5 * present_context

        root = exp["root_cause"]
        root_score_map[root] = max(root_score_map.get(root, 0.0), score)

    best_root_cause = (
        max(root_score_map.items(), key=lambda x: x[1])[0]
        if root_score_map
        else "Unknown"
    )

    if verbose:
        print("[DEBUG] Weighted root_cause scores:", root_score_map)

    # Noisy-OR aggregation of confidence from all matching rules
    combined_confidence = 1.0
    for exp, _ in explanations:
        combined_confidence *= 1.0 - exp.get("confidence", 0.0)
    combined_confidence = 1.0 - combined_confidence

    # Merge all evidence, likely_causes, suggested_checks
    merged_explanation = {
        "pod": pod_name,
        "phase": pod_phase,
        "root_cause": best_root_cause,
        "confidence": combined_confidence,
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
    }

    for exp, _ in explanations:
        merged_explanation["evidence"].extend(exp.get("evidence", []))
        merged_explanation["likely_causes"].extend(exp.get("likely_causes", []))
        merged_explanation["suggested_checks"].extend(exp.get("suggested_checks", []))

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
