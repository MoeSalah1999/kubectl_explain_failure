import glob
import importlib.util
import os
from typing import Any

import yaml

from kubectl_explain_failure.rules.base_rule import FailureRule

# ----------------------------
# Dynamic Rule Loader
# ----------------------------


class YamlFailureRule(FailureRule):
    def __init__(self, spec: dict[str, Any]):
        self.name = spec["name"]
        self.category = spec.get("category", "Generic")
        self.severity = spec.get("severity", "Medium")
        self.priority = spec.get("priority", 100)
        self.spec = spec

    def matches(self, pod, events, context) -> bool:
        expr = self.spec["if"]
        # VERY conservative evaluation
        safe_context: dict[str, dict[str, Any]] = {
            "pod": pod or {},
            "events": events or {},
            "context": context or {},
            "node": context.get("node", {}) or {},
            "pvc": context.get("pvc", {}) or {},
        }
        # Ensure safe nesting
        for obj in ("pod", "node", "pvc"):
            safe_context[obj].setdefault("metadata", {})
            safe_context[obj].setdefault("status", {})

        return eval(expr, {}, safe_context)

    def explain(self, pod, events, context):
        return {
            "root_cause": self.spec["then"]["root_cause"],
            "confidence": float(self.spec["then"].get("confidence", 0.5)),
            "evidence": self.spec["then"].get("evidence", []),
            "likely_causes": self.spec["then"].get("likely_causes", []),
            "suggested_checks": self.spec["then"].get("suggested_checks", []),
        }


def build_yaml_rule(spec: dict[str, Any]) -> FailureRule:
    return YamlFailureRule(spec)


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
            rules.append(build_yaml_rule(spec))

    return rules


def load_plugins(plugin_folder=None) -> list[FailureRule]:
    """Load additional rules from plugins folder (optional)"""
    if plugin_folder is None or not os.path.exists(plugin_folder):
        return []
    return load_rules(plugin_folder)
