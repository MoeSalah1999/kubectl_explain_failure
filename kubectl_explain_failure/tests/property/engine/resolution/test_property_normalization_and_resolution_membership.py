import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.rules.base.container.crashloop_backoff import (
    CrashLoopBackOffRule,
)
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    snapshot_strategy,
)

RULES = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]


@given(snapshot=snapshot_strategy())
def test_property_normalize_context_is_idempotent(snapshot: K8sSnapshot):
    _, _, context = snapshot.as_engine_input()

    once = normalize_context(copy.deepcopy(context))
    twice = normalize_context(copy.deepcopy(once))

    assert twice == once


@given(snapshot=snapshot_strategy())
def test_property_pod_object_graph_merge_equivalent_to_context_objects(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    base_result = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    context_objects = copy.deepcopy(context.get("objects", {}))

    pod_variant = copy.deepcopy(pod)
    if context_objects:
        pod_variant["objects"] = context_objects

    context_variant = copy.deepcopy(context)
    context_variant.pop("objects", None)

    merged_result = explain_failure(
        pod_variant,
        copy.deepcopy(events),
        context=context_variant,
        rules=RULES,
    )

    assert merged_result["root_cause"] == base_result["root_cause"]
    assert merged_result["blocking"] == base_result["blocking"]

    base_resolution = base_result.get("resolution")
    merged_resolution = merged_result.get("resolution")
    assert (base_resolution is None) == (merged_resolution is None)
    if base_resolution and merged_resolution:
        assert merged_resolution.get("winner") == base_resolution.get("winner")


@st.composite
def _legacy_node_context(draw) -> tuple[dict, list[str]]:
    node_name = draw(
        st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122),
            min_size=1,
            max_size=10,
        )
    )
    condition_types = draw(
        st.lists(
            st.sampled_from(["Ready", "DiskPressure", "MemoryPressure", "PIDPressure"]),
            min_size=1,
            max_size=4,
            unique=True,
        )
    )

    conditions = []
    for cond_type in condition_types:
        conditions.append(
            {
                "type": cond_type,
                "status": draw(st.sampled_from(["True", "False", "Unknown"])),
                "reason": draw(st.text(max_size=30)),
                "message": draw(st.text(max_size=80)),
                "lastTransitionTime": "2024-01-01T00:00:00Z",
            }
        )

    context = {
        "node": {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {"name": node_name},
            "status": {"conditions": conditions},
        }
    }
    return context, condition_types


@st.composite
def _legacy_pvc_list_context(draw) -> tuple[dict, bool]:
    names = draw(
        st.lists(
            st.text(
                alphabet=st.characters(min_codepoint=97, max_codepoint=122),
                min_size=1,
                max_size=8,
            ),
            min_size=1,
            max_size=4,
            unique=True,
        )
    )
    phases = draw(
        st.lists(
            st.sampled_from(["Bound", "Pending", "Lost"]),
            min_size=len(names),
            max_size=len(names),
        )
    )

    pvc_list = []
    for name, phase in zip(names, phases, strict=False):
        pvc_list.append(
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": name},
                "status": {"phase": phase},
            }
        )

    has_unbound = any(phase != "Bound" for phase in phases)
    return {"pvc": pvc_list}, has_unbound


@given(payload=_legacy_node_context())
def test_property_legacy_node_populates_object_graph_and_node_conditions(payload):
    legacy_context, condition_types = payload

    normalized = normalize_context(copy.deepcopy(legacy_context))

    node_name = legacy_context["node"]["metadata"]["name"]
    assert "objects" in normalized
    assert "node" in normalized["objects"]
    assert node_name in normalized["objects"]["node"]

    node_conditions = normalized.get("node_conditions", {})
    assert isinstance(node_conditions, dict)
    assert set(node_conditions.keys()) == set(condition_types)


@given(payload=_legacy_pvc_list_context())
def test_property_legacy_pvc_list_normalizes_and_sets_blocking_flags(payload):
    legacy_context, has_unbound = payload

    normalized = normalize_context(copy.deepcopy(legacy_context))

    input_pvcs = legacy_context["pvc"]
    names = [p["metadata"]["name"] for p in input_pvcs]

    assert "objects" in normalized
    assert "pvc" in normalized["objects"]
    assert set(normalized["objects"]["pvc"].keys()) == set(names)

    if has_unbound:
        assert normalized.get("pvc_unbound") is True
        blocking = normalized.get("blocking_pvc")
        assert isinstance(blocking, dict)
        assert blocking.get("status", {}).get("phase") != "Bound"
        assert normalized.get("pvc") == blocking
