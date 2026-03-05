import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, given, settings, strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule

RULES = [PVCNotBoundRule(), FailedSchedulingRule()]


def _pod_pending() -> dict:
    return {
        "metadata": {"name": "ctx-pod", "namespace": "default"},
        "status": {"phase": "Pending"},
    }


def _pvc(phase: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "test-pvc"},
        "status": {"phase": phase},
    }


@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(
    use_legacy_pvc=st.booleans(),
    use_graph_pvc=st.booleans(),
    pvc_phase=st.sampled_from(["Pending", "Bound"]),
    events=st.lists(
        st.fixed_dictionaries(
            {
                "reason": st.sampled_from(
                    ["FailedScheduling", "NodeNotReady", "Created", "Started"]
                ),
                "message": st.text(max_size=80),
            }
        ),
        max_size=12,
    ),
)
def test_property_context_shapes_are_handled_consistently(
    use_legacy_pvc: bool,
    use_graph_pvc: bool,
    pvc_phase: str,
    events: list[dict],
):
    context: dict = {}
    pvc_obj = _pvc(pvc_phase)

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
    if pvc_present and pvc_phase == "Pending":
        assert result["blocking"] is True
        assert "persistentvolumeclaim" in result["root_cause"].lower()
