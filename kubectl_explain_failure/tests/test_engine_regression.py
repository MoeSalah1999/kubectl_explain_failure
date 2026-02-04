import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine import explain_failure
from model import get_pod_name


# Minimal fake rules for testing without real cluster
class FakeRuleOOM:
    name = "oom_rule"
    category = "container"
    requires = {"pod": True}  # no events required
    phases = ["Running"]

    def matches(self, pod, events, context):
        # match if lastState.terminated.reason == 'OOMKilled'
        for c in pod.get("status", {}).get("containerStatuses", []):
            term = c.get("lastState", {}).get("terminated", {})
            if term.get("reason") == "OOMKilled":
                return True
        return False

    def explain(self, pod, events, context):
        return {
            "root_cause": "Out-of-memory",
            "confidence": 0.9,
            "evidence": ["container terminated with OOMKilled"],
            "likely_causes": ["pod exceeded memory limit"],
            "suggested_checks": ["Check pod memory limits"],
        }


class FakeRulePVC:
    name = "pvc_rule"
    category = "volume"
    requires = {"context": ["pvc"]}
    phases = ["Pending"]

    def matches(self, pod, events, context):
        pvc = context.get("pvc")
        return pvc and pvc.get("status") != "Bound"

    def explain(self, pod, events, context):
        return {
            "root_cause": "Pod is blocked by unbound PVC",
            "confidence": 0.8,
            "evidence": ["PVC not bound"],
            "likely_causes": ["Storage provisioning delayed"],
            "suggested_checks": ["Check PVC status"],
        }


@pytest.mark.parametrize(
    "rule_class, pod, context, expected_root",
    [
        (
            FakeRuleOOM,
            {
                "metadata": {"name": "oom-pod"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {"lastState": {"terminated": {"reason": "OOMKilled"}}}
                    ],
                },
            },
            {},
            "Out-of-memory",
        ),
        (
            FakeRulePVC,
            {"metadata": {"name": "pending-pod"}, "status": {"phase": "Pending"}},
            {"pvc": {"status": "Pending"}},
            "Pod is blocked by unbound PVC",
        ),
    ],
)
def test_regression_eventless_rules(rule_class, pod, context, expected_root):
    """
    Regression test for Fix #2:
    Ensure rules with no events requirement fire correctly when events=[].
    """
    rules = [rule_class()]
    result = explain_failure(pod, events=[], context=context, rules=rules)
    assert expected_root.lower() in result["root_cause"].lower()
    assert result["confidence"] > 0
    assert isinstance(result["evidence"], list)
    assert isinstance(result["likely_causes"], list)
    assert isinstance(result["suggested_checks"], list)
