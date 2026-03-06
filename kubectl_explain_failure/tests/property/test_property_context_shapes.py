import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given, strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule
from kubectl_explain_failure.tests.property.strategies import event_strategy, pvc_strategy

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

    pvc_present = use_legacy_pvc or use_graph_pvc
    pvc_phase = pvc_obj.get("status", {}).get("phase")
    if pvc_present and pvc_phase == "Pending":
        assert result["blocking"] is True
        assert "persistentvolumeclaim" in result["root_cause"].lower()
