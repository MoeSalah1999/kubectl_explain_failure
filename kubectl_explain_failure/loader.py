import glob
import importlib.util
import os
from collections.abc import Iterable
from typing import Any

import yaml

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern

# ----------------------------
# Dynamic Rule Loader
# ----------------------------


class YamlFailureRule(FailureRule):
    def __init__(self, spec: dict[str, Any]):
        self.name = spec["name"]
        self.category = spec.get("category", "Generic")
        self.severity = spec.get("severity", "Medium")
        self.priority = spec.get("priority", 100)
        self.requires = spec.get("requires", {})  # 🔧 REQUIRED
        self.spec = spec

    @staticmethod
    def _normalize_k8s_object(obj: Any) -> None:
        if not isinstance(obj, dict):
            return

        obj.setdefault("metadata", {})
        if isinstance(obj["metadata"], dict):
            obj["metadata"].setdefault("labels", {})

        obj.setdefault("status", {})

    def matches(self, pod, events, context) -> bool:
        events_list = list(events) if isinstance(events, Iterable) else []

        safe_context: dict[str, Any] = {
            "pod": pod or {},
            "events": events_list,
            "context": context or {},
            "node": (context or {}).get("node", {}) or {},
            "pvc": (context or {}).get("pvc", {}) or {},
        }

        # Normalize top-level objects
        for obj in ("pod", "node", "pvc"):
            YamlFailureRule._normalize_k8s_object(safe_context[obj])

        # Normalize objects inside context as well
        if isinstance(safe_context["context"], dict):
            for v in safe_context["context"].values():
                YamlFailureRule._normalize_k8s_object(v)

        eval_globals = {
            "timeline_has_pattern": timeline_has_pattern,
        }

        return eval(self.spec.get("if", "False"), eval_globals, safe_context)

    def explain(self, pod, events, context):
        then = self.spec.get("then", {})

        chain = None
        if "causes" in then:
            chain = CausalChain(
                causes=[
                    Cause(
                        code=c.get("code", c["message"].upper().replace(" ", "_")),
                        message=c["message"],
                        blocking=c.get("blocking", False),
                    )
                    for c in then["causes"]
                ]
            )

        return {
            "root_cause": then.get("root_cause", "Unknown"),
            "confidence": float(then.get("confidence", 0.5)),
            "evidence": then.get("evidence", []),
            "likely_causes": then.get("likely_causes", []),
            "suggested_checks": then.get("suggested_checks", []),
            **({"causes": chain} if chain else {}),
        }


def build_yaml_rules(spec: Any) -> list[FailureRule]:
    """
    Accepts either a single dict or a list of dicts from YAML file.
    Returns a list of YamlFailureRule instances.
    """
    rules: list[FailureRule] = []
    if not spec:
        return rules
    if isinstance(spec, dict):
        rules.append(YamlFailureRule(spec))
    elif isinstance(spec, list):
        for item in spec:
            if not isinstance(item, dict):
                raise ValueError("Each YAML rule must be a dict")
            rules.append(YamlFailureRule(item))
    else:
        raise ValueError("YAML content must be a dict or a list of dicts")
    return rules


def validate_rule(rule: FailureRule):
    required_fields = ["name", "category", "priority", "requires"]
    for field in required_fields:
        if not hasattr(rule, field):
            raise ValueError(f"Rule {rule} missing required field '{field}'")

    if not isinstance(rule.name, str) or not rule.name:
        raise ValueError("Rule.name must be a non-empty string")
    if not isinstance(rule.category, str) or not rule.category:
        raise ValueError(f"Rule {rule.name}.category must be a non-empty string")
    if not isinstance(rule.priority, int):
        raise ValueError(f"Rule {rule.name}.priority must be an integer")
    if not (0 <= rule.priority <= 1000):
        raise ValueError(f"Rule {rule.name}.priority must be between 0 and 1000")
    if not isinstance(rule.requires, dict):
        raise ValueError(f"Rule {rule.name}.requires must be a dict")

    allowed_keys = {"pod", "events", "context", "objects", "optional_objects"}
    unknown = set(rule.requires) - allowed_keys
    if unknown:
        raise ValueError(
            f"Rule {rule.name}.requires has invalid keys: {sorted(unknown)}"
        )

    if "objects" in rule.requires and not isinstance(rule.requires["objects"], list):
        raise ValueError(f"Rule {rule.name}.requires.objects must be a list")
    if "optional_objects" in rule.requires and not isinstance(
        rule.requires["optional_objects"], list
    ):
        raise ValueError(f"Rule {rule.name}.requires.optional_objects must be a list")


def load_rules(rule_folder=None) -> list[FailureRule]:
    if rule_folder is None:
        rule_folder = os.path.join(os.path.dirname(__file__), "rules")

    rules: list[FailureRule] = []

    # ---- Python rules ----
    for file in glob.glob(os.path.join(rule_folder, "*.py")):
        if os.path.basename(file) == "base_rule.py":
            continue
        module_name = os.path.splitext(os.path.basename(file))[0]
        spec = importlib.util.spec_from_file_location(module_name, file)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for attr in dir(module):
            cls = getattr(module, attr)
            if (
                isinstance(cls, type)
                and issubclass(cls, FailureRule)
                and cls is not FailureRule
            ):
                rules.append(cls())

    # ---- YAML rules ----
    for yfile in glob.glob(os.path.join(rule_folder, "*.yaml")):
        with open(yfile, encoding="utf-8") as f:
            spec = yaml.safe_load(f)
            if spec:  # skip empty YAML files
                rules.extend(build_yaml_rules(spec))  # support multiple rules per file

    # ---- CONTRACT VALIDATION ----
    for rule in rules:
        validate_rule(rule)

    return rules


def load_plugins(plugin_folder=None) -> list[FailureRule]:
    if plugin_folder is None or not os.path.exists(plugin_folder):
        return []
    return load_rules(plugin_folder)
