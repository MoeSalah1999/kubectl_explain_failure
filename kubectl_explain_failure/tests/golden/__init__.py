import pytest

from kubectl_explain_failure.loader import validate_rule


class NoRequiresRule:
    name = "Bad"
    category = "Test"
    priority = 1


def test_rule_missing_requires_is_rejected():
    with pytest.raises(ValueError):
        validate_rule(NoRequiresRule())
