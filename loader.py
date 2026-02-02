import os
import glob
import yaml
import importlib.util
from typing import List, Dict, Any
from rules.base_rule import FailureRule


def load_plugins(plugin_folder: str):
    plugin_rules = []
    if not os.path.exists(plugin_folder):
        return plugin_rules

    for py_file in glob.glob(os.path.join(plugin_folder, "*.py")):
        if py_file.endswith("__init__.py"):
            continue
        module_name = os.path.splitext(os.path.basename(py_file))[0]
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for attr in dir(mod):
            obj = getattr(mod, attr)
            try:
                if issubclass(obj, FailureRule) and obj is not FailureRule:
                    plugin_rules.append(obj())
            except TypeError:
                continue
    return plugin_rules

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


