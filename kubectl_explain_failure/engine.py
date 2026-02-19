import os
from typing import Any

from kubectl_explain_failure.causality import (
    CausalChain,
    Resolution,
    build_chain,
)
from kubectl_explain_failure.context import _extract_node_conditions
from kubectl_explain_failure.loader import load_plugins, load_rules
from kubectl_explain_failure.model import get_pod_name, get_pod_phase
from kubectl_explain_failure.relations import build_relations
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline, timeline_has_pattern

_DEFAULT_RULES = None


def get_default_rules() -> list[FailureRule]:
    global _DEFAULT_RULES
    if _DEFAULT_RULES is None:
        rules_path = os.path.join(os.path.dirname(__file__), "rules")
        plugin_path = os.path.join(os.path.dirname(__file__), "plugins")
        _DEFAULT_RULES = sorted(
            load_rules(rules_path) + load_plugins(plugin_path),
            key=lambda r: getattr(r, "priority", 100),
            reverse=True,
        )
    return _DEFAULT_RULES


def _norm_category(rule: FailureRule) -> str:
    return (getattr(rule, "category", "") or "").strip().lower()


def normalize_context(context: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize legacy top-level 'pvc', 'node', etc. into the new object-graph format.
    Ensures every object has a name.
    Also preserves top-level keys for backward compatibility.
    """
    objects = context.get("objects", {})

    # PVC
    if "pvc" in context:
        pvc_data = context["pvc"]
        if isinstance(pvc_data, dict):
            name = pvc_data.get("metadata", {}).get("name", "pvc1")
            objects.setdefault("pvc", {})[name] = pvc_data
        elif isinstance(pvc_data, list):
            objects.setdefault("pvc", {}).update(
                {
                    p.get("metadata", {}).get("name", f"pvc{i}"): p
                    for i, p in enumerate(pvc_data)
                }
            )

    # Node
    # Node
    if "node" in context:
        node_data = context["node"]

        # Case 1: Object-graph format (name -> node_object)
        if isinstance(node_data, dict) and "metadata" not in node_data:
            objects.setdefault("node", {}).update(node_data)

        # Case 2: Single Kubernetes-shaped node object
        elif isinstance(node_data, dict):
            name = node_data.get("metadata", {}).get("name", "node1")
            objects.setdefault("node", {})[name] = node_data

        # Case 3: List of node objects
        elif isinstance(node_data, list):
            objects.setdefault("node", {}).update(
                {
                    n.get("metadata", {}).get("name", f"node{i}"): n
                    for i, n in enumerate(node_data)
                }
            )

        # Populate node_conditions for legacy rules
        node_objects = list(objects.get("node", {}).values())
        if node_objects:
            merged = {}
            for n in node_objects:
                merged.update(_extract_node_conditions(n))
            context["node_conditions"] = merged


        # Populate node_conditions for NodeDiskPressureRule
        node_objects = list(objects.get("node", {}).values())
        if node_objects:
            # Merge conditions across nodes (defensive)
            merged = {}
            for n in node_objects:
                merged.update(_extract_node_conditions(n))
            context["node_conditions"] = merged
            # Preserve objects in context
            context["objects"] = objects

    # Preserve legacy top-level keys for backward compatibility
    # IMPORTANT: legacy rules expect SINGLE objects, not name->object mappings
    if "pvc" in context and isinstance(context["pvc"], dict):
        # leave context["pvc"] as the original single PVC object
        pass

    if "node" in context and isinstance(context["node"], dict):
        # leave context["node"] as the original single Node object
        pass

    # ----------------------------
    # Canonical PVC state (object-graph based)
    # ----------------------------
    pvc_objects = objects.get("pvc", {})

    unbound_pvcs = []
    for pvc in pvc_objects.values():
        status = pvc.get("status")

        # Kubernetes-shaped PVC
        if isinstance(status, dict):
            phase = status.get("phase")
        # Legacy / test stub PVC
        elif isinstance(status, str):
            phase = status
        else:
            phase = None

        if phase != "Bound":
            unbound_pvcs.append(pvc)

    if unbound_pvcs:
        blocking = unbound_pvcs[0]

        # Canonical signals
        context["blocking_pvc"] = blocking
        context["pvc_unbound"] = True

        # Legacy compatibility (many rules rely on this)
        context["pvc"] = blocking

    # Ensure objects are preserved
    context["objects"] = objects

    return context


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

    def suppression_rank(item):
        _, rule, _ = item
        # Compound rules always suppress first
        if getattr(rule, "category", None) == "Compound":
            return (0, -getattr(rule, "priority", 0))
        return (1, -getattr(rule, "priority", 0))

    for exp, rule, chain in sorted(
        explanations,
        key=suppression_rank,
    ):
        if rule.name in blocked_rules:
            continue

        # Determine which rules this winner blocks
        blocks = list(getattr(rule, "blocks", []))

        # Compound rules subsume container-level crash signals
        if getattr(rule, "category", None) == "Compound":
            blocks += [
                "CrashLoopBackOff",
                "RepeatedCrashLoop",
                "OOMKilled",
            ]

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
    # -------------------------------------------------
    # MERGE pod-level object graph into context
    # -------------------------------------------------
    if context is None:
        context = {}

    pod_objects = pod.get("objects")
    if isinstance(pod_objects, dict):
        ctx_objects = context.setdefault("objects", {})
        for kind, objs in pod_objects.items():
            if isinstance(objs, dict):
                ctx_objects.setdefault(kind, {}).update(objs)

    # Preserve blocking_pvc if provided at pod level (fixtures, API users)
    if "blocking_pvc" not in context and "blocking_pvc" in pod:
        context["blocking_pvc"] = pod["blocking_pvc"]

    context = normalize_context(context or {})
    objects = context.get("objects", {})
    rules = rules or get_default_rules()

    pod_name = get_pod_name(pod)
    pod_phase = get_pod_phase(pod)

    context["relations"] = build_relations(pod, context)
    if events:
        context["timeline"] = build_timeline(events)

    if context.get("timeline") and timeline_has_pattern(
        context["timeline"], [{"reason": "BackOff"}]
    ):
        # optional debug log
        if verbose:
            print(f"[DEBUG] Timeline shows BackOff pattern for pod {pod_name}")

    owners = pod.get("metadata", {}).get("ownerReferences", [])
    if owners:
        context["owners"] = owners

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
        phases = getattr(rule, "phases", None) or getattr(
            rule, "supported_phases", None
        )
        if phases and pod_phase not in phases:
            continue

        # Container-state gating
        required_states = getattr(rule, "container_states", None)
        if required_states:
            state_match = False

            for s in container_states:
                for required in required_states:
                    if required in s:
                        state_match = True
                        break
                if state_match:
                    break

            if not state_match:
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

        # ----------------------------
        # Contract enforcement (OBJECT-GRAPH AWARE)
        # ----------------------------
        requires = getattr(rule, "requires", {})

        if requires.get("pod") and not pod:
            continue

        # Allow event-driven rules (e.g. FailedMount) to run without context
        missing_context = []
        for key in requires.get("context", []):
            # check new object graph first
            if key in context.get("objects", {}) and context["objects"][key]:
                continue
            # fallback: legacy top-level context
            if key in context and context[key]:
                continue
            # fallback: allow event-driven rules to run if events exist
            if events:
                continue
            # missing required context
            missing_context.append(key)

        if missing_context:
            # Allow purely event-driven rules
            if events:
                continue
            if verbose:
                print(
                    f"[DEBUG] Skipping '{rule.name}': "
                    f"missing context keys {missing_context}"
                )
            continue

        # Object dependency requirement
        required_objects = requires.get("objects", [])
        objects = context.get("objects", {})

        # Presence-based object contract:
        # - object kind must exist in the graph
        # - contents MAY be empty (e.g. missing ConfigMap/Secret)
        missing_objects = [obj for obj in required_objects if obj not in objects]

        if missing_objects:
            if verbose:
                print(
                    f"[DEBUG] Skipping '{rule.name}': missing required objects {missing_objects}"
                )
            continue

        # ----------------------------
        # OPTIONAL object enrichment
        # ----------------------------
        optional_objects = requires.get("optional_objects", [])
        if optional_objects:
            present_optional = [
                obj
                for obj in optional_objects
                if obj in context.get("objects", {}) and context["objects"][obj]
            ]
            context.setdefault("optional_objects_present", {})[
                rule.name
            ] = present_optional

        if events:
            context = context or {}
            context.setdefault("timeline", build_timeline(events))

        # Rule match
        if rule.matches(pod, events, context):
            exp = rule.explain(pod, events, context)

            # ---- Explain() contract enforcement ----
            if not isinstance(exp, dict):
                raise TypeError(f"{rule.name}.explain() must return a dict")

            if "root_cause" not in exp or not isinstance(exp["root_cause"], str):
                raise ValueError(
                    f"{rule.name}.explain() must include 'root_cause' (str)"
                )

            confidence = exp.get("confidence", 0.0)
            if not isinstance(confidence, (int, float)):
                raise ValueError(f"{rule.name}.confidence must be numeric")

            exp["confidence"] = float(confidence)

            for key in ("evidence", "likely_causes", "suggested_checks"):
                if key in exp and not isinstance(exp[key], list):
                    raise ValueError(f"{rule.name}.{key} must be a list")

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
            "blocking": False,
        }

    # ----------------------------
    # Apply automatic suppression
    # ----------------------------
    filtered_explanations, suppression_map = apply_suppressions(explanations)

    # ----------------------------------------
    # Conflict penalty injection (deterministic)
    # ----------------------------------------
    total_matches = len(filtered_explanations)
    if total_matches > 1:
        # Penalize non-dominant rules slightly to reflect ambiguity
        penalty = 1.0 - (0.05 * (total_matches - 1))
        penalty = max(0.75, penalty)  # never degrade below 0.75

        for exp, rule, _ in filtered_explanations:
            exp["confidence"] = compose_confidence(
                rule_confidence=exp.get("confidence", 0.0),
                conflict_penalty=penalty,
            )

    # ----------------------------
    # HARD DOMINANCE: Compound rules define root cause
    # ----------------------------
    compound_matches = [
        (exp, rule, chain)
        for exp, rule, chain in filtered_explanations
        if _norm_category(rule) == "compound"
    ]

    if compound_matches:
        # Determine highest non-compound priority
        max_non_compound_priority = max(
            (
                getattr(rule, "priority", 0)
                for _, rule, _ in filtered_explanations
                if _norm_category(rule) != "compound"
            ),
            default=0,
        )

        max_compound_priority = max(
            getattr(rule, "priority", 0)
            for _, rule, _ in compound_matches
        )

        # Compound dominance only applies if it truly outranks others
        if max_compound_priority >= max_non_compound_priority:
            best_exp, best_rule, best_chain = max(
                compound_matches,
                key=lambda pair: getattr(pair[1], "priority", 0),
            )
            suppressed_rules = {r.name for _, r, _ in explanations if r is not best_rule}

            resolution = Resolution(
                winner=best_rule.name,
                suppressed=sorted(suppressed_rules),
                reason="Compound causal chain dominates component failures",
            )

            result = {
                "pod": pod_name,
                "phase": pod_phase,
                "root_cause": best_exp["root_cause"],
                "confidence": best_exp.get("confidence", 1.0),
                "evidence": best_exp.get("evidence", []),
                "likely_causes": best_exp.get("likely_causes", []),
                "suggested_checks": best_exp.get("suggested_checks", []),
                "resolution": resolution.__dict__,
                "blocking": False,
            }

            # ----------------------------
            # PVC semantics (LOCKED)
            # ----------------------------
            # Rule-level blocking intent (authoritative)
            if best_exp.get("blocking") is True:
                result["blocking"] = True
            # Engine-derived blocking (PVC scheduling is hard-blocking)
            elif context.get("blocking_pvc") is not None:
                result["blocking"] = True

            if "object_evidence" in best_exp:
                result["object_evidence"] = best_exp["object_evidence"]

            # ----------------------------
            # Causal chain materialization (LOCKED)
            # ----------------------------
            result["causes"] = [
                {
                    "code": cause.code,
                    "message": cause.message,
                    **({"blocking": True} if cause.blocking else {}),
                    **({"role": cause.role} if getattr(cause, "role", None) else {}),
                }
                for cause in best_chain.causes
            ]

            # ----------------------------
            # Object evidence (RULE FIRST, ENGINE FALLBACK)
            # ----------------------------
            if "object_evidence" in best_exp:
                # Trust rule-provided structure verbatim
                result["object_evidence"] = best_exp["object_evidence"]
            else:
                # Engine-level fallback synthesis (only if rule omitted it)
                pvc = context.get("blocking_pvc") or context.get("pvc")
                if isinstance(pvc, dict):
                    name = pvc.get("metadata", {}).get("name")
                    phase = pvc.get("status", {}).get("phase")
                    if name and phase:
                        result["object_evidence"] = {
                            f"pvc:{name}, phase:{phase}": ["PVC not Bound"]
                        }
            return result
        
        else:
            compound_matches = []  # fall through to weighted selection


    if not filtered_explanations:
        return {
            "pod": pod_name,
            "phase": pod_phase,
            "root_cause": "Unknown",
            "evidence": [],
            "likely_causes": [],
            "suggested_checks": [],
            "confidence": 0.0,
            "blocking": False,
        }

    # ----------------------------
    # STRONG CAUSAL OVERRIDE: PVC blocks scheduling
    # ----------------------------
    pvc_matches = [
        (exp, rule, chain)
        for exp, rule, chain in filtered_explanations
        if getattr(rule, "category", None) == "PersistentVolumeClaim"
    ]

    # Only consider PVCs that are unbound or have provisioning issues
    pvc_matches = [
        (exp, rule, chain)
        for exp, rule, chain in pvc_matches
        if context.get("pvc_unbound") or exp.get("root_cause", "").startswith("PVC cannot be provisioned")
    ]

    if pvc_matches:
        # Pick the highest priority * confidence PVC rule
        best_exp, best_rule, best_chain = max(
            pvc_matches,
            key=lambda pair: pair[0].get("confidence", 0.0) * getattr(pair[1], "priority", 1),
        )

        # Defensive PVC name extraction
        pvc_name = "<unknown>"
        pvc_objs = context.get("objects", {}).get("pvc", {})
        if pvc_objs:
            pvc_obj = next(iter(pvc_objs.values()))
            pvc_name = pvc_obj.get("metadata", {}).get("name", "<unknown>")

        confidence = max(best_exp.get("confidence", 0.0), 0.95)

        # Suppress other rules
        suppressed_rules = {r.name for _, r, _ in explanations if r is not best_rule}
        suppressed_rules.update(suppression_map.get(best_rule.name, []))

        resolution = Resolution(
            winner=best_rule.name,
            suppressed=sorted(suppressed_rules),
            reason="PersistentVolumeClaim is a hard scheduling blocker",
        )

        result = {
            "pod": pod_name,
            "phase": pod_phase,
            "pvc_name": pvc_name,
            "root_cause": best_exp.get("root_cause", "Unknown"),
            "confidence": confidence,
            "evidence": best_exp.get("evidence", []),
            "likely_causes": best_exp.get("likely_causes", []),
            "suggested_checks": best_exp.get("suggested_checks", []),
            "resolution": resolution.__dict__,
            "blocking": True,
            # TRUST rule-provided object evidence
            "object_evidence": best_exp.get("object_evidence", {}),
            "causes": [
                {
                    "code": c.code,
                    "message": c.message,
                    **({"blocking": True} if c.blocking else {}),
                    **({"role": c.role} if getattr(c, "role", None) else {}),
                }
                for c in best_chain.causes
            ],
        }

        return result
    
    # -------------------------------------------------
    # DETERMINISTIC RULE SHORT-CIRCUIT
    # If exactly one rule remains and it is deterministic,
    # preserve its confidence and bypass noisy-OR aggregation.
    # -------------------------------------------------
    if len(filtered_explanations) == 1:
        exp, rule, chain = filtered_explanations[0]

        if getattr(rule, "deterministic", False):
            result = {
                "pod": pod_name,
                "phase": pod_phase,
                "root_cause": exp.get("root_cause", "Unknown"),
                "confidence": float(exp.get("confidence", 1.0)),
                "evidence": exp.get("evidence", []),
                "likely_causes": exp.get("likely_causes", []),
                "suggested_checks": exp.get("suggested_checks", []),
                "blocking": bool(exp.get("blocking", False)),
                "causes": [
                    {
                        "code": c.code,
                        "message": c.message,
                        **({"blocking": True} if c.blocking else {}),
                        **({"role": c.role} if getattr(c, "role", None) else {}),
                    }
                    for c in chain.causes
                ],
                "resolution": {
                    "winner": rule.name,
                    "suppressed": suppression_map.get(rule.name, []),
                    "reason": "Deterministic rule matched with high confidence",
                },
            }

            if "object_evidence" in exp:
                result["object_evidence"] = exp["object_evidence"]

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
    for exp, _, _ in filtered_explanations:
        signal_strength *= 1.0 - exp.get("confidence", 0.0)
    signal_strength = 1.0 - signal_strength

    data_completeness = min(1.0, len(context) / 5.0)
    conflict_penalty = 1.0 - (0.1 * max(0, len(filtered_explanations) - 1))

    combined_confidence = signal_strength * data_completeness * conflict_penalty

    # ----------------------------
    # Merge explanations
    # ----------------------------

    # Determine winner for suppression
    winner_rule_name = filtered_explanations[0][1].name
    merged_suppressed_rules = [
        r.name for _, r, _ in filtered_explanations[1:]
    ] + suppression_map.get(winner_rule_name, [])

    # Determine winner rule object
    winner_exp = next(
        (exp for exp, r, _ in filtered_explanations if r.name == winner_rule_name),
        {},
    )

    merged: dict[str, Any] = {
        "pod": pod_name,
        "phase": pod_phase,
        "root_cause": best_root_cause,
        "confidence": combined_confidence,
        "evidence": [],
        "likely_causes": [],
        "suggested_checks": [],
        "causes": [],
        "resolution": {
            "winner": winner_rule_name,
            "suppressed": merged_suppressed_rules,
            "reason": "Automatic suppression applied based on rule.blocks",
        },
        "blocking": bool(winner_exp.get("blocking", False)),
    }

    for exp, _, chain in explanations:
        merged["evidence"].extend(list(exp.get("evidence", [])))
        merged["likely_causes"].extend(list(exp.get("likely_causes", [])))
        merged["suggested_checks"].extend(list(exp.get("suggested_checks", [])))
        for cause in chain.causes:
            merged["causes"].append(
                {
                    "code": cause.code,
                    "message": cause.message,
                    **({"blocking": True} if cause.blocking else {}),
                    **({"role": cause.role} if getattr(cause, "role", None) else {}),
                }
            )

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
    # Deduplicate causes by (code, message)
    seen = set()
    unique_causes = []
    for c in merged["causes"]:
        key = (c["code"], c["message"])
        if key not in seen:
            seen.add(key)
            unique_causes.append(c)
    merged["causes"] = unique_causes


    if "object_evidence" in merged:
        for obj, items in merged["object_evidence"].items():
            merged["object_evidence"][obj] = list(dict.fromkeys(items))

    # Sanity dampening
    if pod_phase == "Pending" and not events:
        merged["confidence"] = float(merged["confidence"]) * 0.5

    merged["confidence"] = min(1.0, max(0.0, merged["confidence"]))

    return merged
