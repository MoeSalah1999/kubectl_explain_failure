import pytest

from kubectl_explain_failure.loader import load_rules, validate_rule
from kubectl_explain_failure.rules.base_rule import FailureRule


class BadPriorityRule(FailureRule):
    name = "BadPriority"
    priority = -1


def test_priority_range_enforced():
    with pytest.raises(ValueError):
        validate_rule(BadPriorityRule())


class BadExplainRule(FailureRule):
    name = "BadExplain"
    requires = {"objects": []}

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {"confidence": "high"}  # invalid


def test_explain_contract_enforced():
    from kubectl_explain_failure.engine import explain_failure

    with pytest.raises(ValueError):
        explain_failure(
            pod={"metadata": {"name": "p"}},
            events=[],
            context={},
            rules=[BadExplainRule()],
        )


def test_all_rules_have_metadata():
    rules = load_rules("kubectl_explain_failure/rules")
    for r in rules:
        assert hasattr(r, "name") and r.name
        assert hasattr(r, "category") and r.category
        assert hasattr(r, "priority")
        assert 0 <= r.priority <= 1000  # sanity check


def test_rules_have_matches_and_explain():
    rules = load_rules("kubectl_explain_failure/rules")
    for r in rules:
        assert callable(getattr(r, "matches", None))
        assert callable(getattr(r, "explain", None))
