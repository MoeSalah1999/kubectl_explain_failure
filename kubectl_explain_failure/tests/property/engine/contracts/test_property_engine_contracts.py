import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base_rule import FailureRule


class _DeterministicRuleA(FailureRule):
    name = "DeterministicA"
    deterministic = True

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "A",
            "confidence": 0.8,
            "evidence": ["a"],
            "likely_causes": ["a"],
            "suggested_checks": ["a"],
        }


class _DeterministicRuleB(FailureRule):
    name = "DeterministicB"
    deterministic = True

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "B",
            "confidence": 0.7,
            "evidence": ["b"],
            "likely_causes": ["b"],
            "suggested_checks": ["b"],
        }


class _OutOfRangeConfidenceRule(FailureRule):
    name = "OutOfRangeConfidence"

    def __init__(self, confidence: float):
        self._confidence = confidence

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "Invalid confidence",
            "confidence": self._confidence,
            "evidence": ["x"],
            "likely_causes": ["x"],
            "suggested_checks": ["x"],
        }


def _pod(phase: str) -> dict:
    return {
        "metadata": {"name": "contract-pod", "namespace": "default"},
        "status": {"phase": phase},
    }


@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
@given(phase=st.sampled_from(["Pending", "Running", "Failed", "Unknown"]))
def test_property_rejects_multiple_deterministic_matches(phase: str):
    with pytest.raises(RuntimeError, match="Multiple deterministic rules matched"):
        explain_failure(
            _pod(phase),
            events=[],
            context={},
            rules=[_DeterministicRuleA(), _DeterministicRuleB()],
        )


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running"]),
    bad_confidence=st.one_of(
        st.floats(max_value=-0.000001, allow_nan=False, allow_infinity=False),
        st.floats(min_value=1.000001, allow_nan=False, allow_infinity=False),
    ),
)
def test_property_rejects_out_of_range_confidence(
    phase: str,
    bad_confidence: float,
):
    with pytest.raises(ValueError, match=r"confidence must be within \[0,1\]"):
        explain_failure(
            _pod(phase),
            events=[],
            context={},
            rules=[_OutOfRangeConfidenceRule(bad_confidence)],
        )
