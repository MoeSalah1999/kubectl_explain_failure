import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    snapshot_strategy,
)


class _BadConfidenceTypeRule(FailureRule):
    name = "BadConfidenceTypeRule"

    def __init__(self, bad_confidence):
        self.bad_confidence = bad_confidence

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "Invalid confidence type",
            "confidence": self.bad_confidence,
            "evidence": ["x"],
            "likely_causes": ["x"],
            "suggested_checks": ["x"],
        }


class _BadCollectionTypeRule(FailureRule):
    name = "BadCollectionTypeRule"

    def __init__(self, bad_key: str, bad_value):
        self.bad_key = bad_key
        self.bad_value = bad_value

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        payload = {
            "root_cause": "Invalid collection type",
            "confidence": 0.7,
            "evidence": ["ok"],
            "likely_causes": ["ok"],
            "suggested_checks": ["ok"],
        }
        payload[self.bad_key] = self.bad_value
        return payload


_NON_NUMERIC_CONFIDENCE = st.one_of(
    st.text(),
    st.lists(st.integers(), max_size=3),
    st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), max_size=3),
    st.none(),
)

_NON_LIST_VALUES = st.one_of(
    st.text(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), max_size=3),
    st.none(),
)


@given(snapshot=snapshot_strategy(), bad_confidence=_NON_NUMERIC_CONFIDENCE)
def test_property_rejects_non_numeric_confidence_type(
    snapshot: K8sSnapshot,
    bad_confidence,
):
    pod, events, context = snapshot.as_engine_input()

    with pytest.raises(ValueError, match=r"confidence must be numeric"):
        explain_failure(
            pod,
            events,
            context=context,
            rules=[_BadConfidenceTypeRule(bad_confidence)],
        )


@given(
    snapshot=snapshot_strategy(),
    bad_key=st.sampled_from(["evidence", "likely_causes", "suggested_checks"]),
    bad_value=_NON_LIST_VALUES,
)
def test_property_rejects_non_list_collections_in_rule_output(
    snapshot: K8sSnapshot,
    bad_key: str,
    bad_value,
):
    pod, events, context = snapshot.as_engine_input()

    with pytest.raises(ValueError, match=rf"{bad_key} must be a list"):
        explain_failure(
            pod,
            events,
            context=context,
            rules=[_BadCollectionTypeRule(bad_key, bad_value)],
        )
