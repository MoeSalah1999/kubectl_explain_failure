import pytest
from loader import load_rules

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
