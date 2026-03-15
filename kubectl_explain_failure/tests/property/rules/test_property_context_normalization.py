import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    pvc_strategy,
    snapshot_strategy,
)


class _AlwaysGenericRule(FailureRule):
    name = "AlwaysGenericRule"
    category = "Generic"
    priority = 10

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "Generic signal",
            "confidence": 0.8,
            "evidence": ["generic"],
            "likely_causes": ["generic"],
            "suggested_checks": ["generic"],
        }


@given(
    legacy_pvc=st.one_of(st.none(), pvc_strategy(name="legacy-pvc")),
    graph_pvcs=st.lists(pvc_strategy(), min_size=0, max_size=3),
)
def test_property_normalize_context_sets_pvc_blockers_consistently(
    legacy_pvc: dict | None,
    graph_pvcs: list[dict],
):
    context: dict = {"objects": {}}

    if legacy_pvc is not None:
        context["pvc"] = copy.deepcopy(legacy_pvc)

    if graph_pvcs:
        context["objects"]["pvc"] = {
            p["metadata"]["name"]: copy.deepcopy(p) for p in graph_pvcs
        }

    normalized = normalize_context(copy.deepcopy(context))

    assert isinstance(normalized.get("objects"), dict)
    assert "pvc" not in normalized["objects"] or isinstance(
        normalized["objects"].get("pvc", {}), dict
    )

    pvc_objects = list(normalized.get("objects", {}).get("pvc", {}).values())
    phases = [p.get("status", {}).get("phase") for p in pvc_objects]
    has_unbound = any(phase != "Bound" for phase in phases)

    if has_unbound:
        assert normalized.get("pvc_unbound") is True
        blocking = normalized.get("blocking_pvc")
        assert isinstance(blocking, dict)
        assert blocking.get("status", {}).get("phase") != "Bound"
        assert normalized.get("pvc") == blocking


@given(snapshot=snapshot_strategy())
def test_property_disabled_category_overrides_enabled_category_overlap(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=[_AlwaysGenericRule()],
        enabled_categories=["Generic"],
        disabled_categories=["Generic"],
    )

    assert result["root_cause"] == "Unknown"
    assert result["confidence"] == 0.0
    assert result["blocking"] is False
    assert "resolution" not in result
