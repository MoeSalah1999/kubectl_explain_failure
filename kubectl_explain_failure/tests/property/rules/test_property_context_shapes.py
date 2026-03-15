import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule
from kubectl_explain_failure.tests.property.strategies import (
    event_strategy,
    pvc_strategy,
)

RULES = [PVCNotBoundRule(), FailedSchedulingRule()]


def _pod_pending() -> dict:
    return {
        "metadata": {"name": "ctx-pod", "namespace": "default"},
        "status": {"phase": "Pending"},
    }


@given(
    use_legacy_pvc=st.booleans(),
    use_graph_pvc=st.booleans(),
    pvc_obj=pvc_strategy(name="test-pvc"),
    events=st.lists(event_strategy(), max_size=12),
)
def test_property_context_shapes_are_handled_consistently(
    use_legacy_pvc: bool,
    use_graph_pvc: bool,
    pvc_obj: dict,
    events: list[dict],
):
    context: dict = {}

    if use_legacy_pvc:
        context["pvc"] = copy.deepcopy(pvc_obj)

    if use_graph_pvc:
        context.setdefault("objects", {})
        context["objects"]["pvc"] = {"test-pvc": copy.deepcopy(pvc_obj)}

    result = explain_failure(
        _pod_pending(),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    assert isinstance(result, dict)
    assert isinstance(result.get("root_cause"), str)
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
    assert isinstance(result.get("blocking"), bool)

    # Canonical equivalence check: legacy PVC context and object-graph PVC context
    # should produce the same decision for identical input signals.
    legacy_context = {"pvc": copy.deepcopy(pvc_obj)}
    graph_context = {"objects": {"pvc": {"test-pvc": copy.deepcopy(pvc_obj)}}}

    legacy_result = explain_failure(
        _pod_pending(),
        copy.deepcopy(events),
        context=legacy_context,
        rules=RULES,
    )
    graph_result = explain_failure(
        _pod_pending(),
        copy.deepcopy(events),
        context=graph_context,
        rules=RULES,
    )

    assert legacy_result["root_cause"] == graph_result["root_cause"]
    assert legacy_result["blocking"] == graph_result["blocking"]

    legacy_resolution = legacy_result.get("resolution")
    graph_resolution = graph_result.get("resolution")
    assert (legacy_resolution is None) == (graph_resolution is None)
    if legacy_resolution and graph_resolution:
        assert legacy_resolution.get("winner") == graph_resolution.get("winner")
