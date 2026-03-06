import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, given, settings, strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base_rule import FailureRule


class _BaseCauseRule(FailureRule):
    name = "BaseCauseRule"
    category = "Generic"
    priority = 20

    def __init__(self, should_match: bool):
        self.should_match = should_match

    def matches(self, pod, events, context):
        return self.should_match

    def explain(self, pod, events, context):
        return {
            "root_cause": "BaseCause",
            "confidence": 0.7,
            "evidence": ["base"],
            "likely_causes": ["base"],
            "suggested_checks": ["base"],
        }


class _DependentRule(FailureRule):
    name = "DependentRule"
    category = "Generic"
    priority = 30
    dependencies = ["BaseCause"]

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "DependentCause",
            "confidence": 0.95,
            "evidence": ["dependent"],
            "likely_causes": ["dependent"],
            "suggested_checks": ["dependent"],
        }


class _PhaseStateRule(FailureRule):
    name = "PhaseStateRule"
    category = "Container"
    priority = 15
    phases = ["Running"]
    container_states = ["waiting"]

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "PhaseStateMatched",
            "confidence": 0.8,
            "evidence": ["state"],
            "likely_causes": ["state"],
            "suggested_checks": ["state"],
        }


def _pod(phase: str, include_waiting: bool) -> dict:
    pod = {
        "metadata": {"name": "gate-pod", "namespace": "default"},
        "status": {"phase": phase},
    }
    if include_waiting:
        pod["status"]["containerStatuses"] = [
            {"name": "app", "state": {"waiting": {"reason": "BackOff"}}}
        ]
    else:
        pod["status"]["containerStatuses"] = [
            {"name": "app", "state": {"running": {}}}
        ]
    return pod


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(base_matches=st.booleans())
def test_property_dependency_rule_only_runs_when_dependency_matched(base_matches: bool):
    result = explain_failure(
        _pod("Running", include_waiting=False),
        events=[],
        context={},
        rules=[_BaseCauseRule(base_matches), _DependentRule()],
    )

    if base_matches:
        assert result["root_cause"] == "DependentCause"
        assert result["resolution"]["winner"] == "DependentRule"
    else:
        assert result["root_cause"] == "Unknown"
        assert "resolution" not in result


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running", "Failed", "Unknown"]),
    include_waiting=st.booleans(),
)
def test_property_phase_and_container_state_gating(
    phase: str,
    include_waiting: bool,
):
    result = explain_failure(
        _pod(phase, include_waiting=include_waiting),
        events=[],
        context={},
        rules=[_PhaseStateRule()],
    )

    should_match = phase == "Running" and include_waiting

    if should_match:
        assert result["root_cause"] == "PhaseStateMatched"
        assert result["resolution"]["winner"] == "PhaseStateRule"
    else:
        assert result["root_cause"] == "Unknown"
        assert "resolution" not in result
