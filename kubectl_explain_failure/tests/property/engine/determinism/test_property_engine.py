import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.container.crashloop_backoff import (
    CrashLoopBackOffRule,
)
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    event_strategy,
    malformed_snapshot_strategy,
    pvc_scheduler_snapshot_strategy,
    pvc_strategy,
    snapshot_strategy,
)

RULES = [
    PVCNotBoundRule(),
    FailedSchedulingRule(),
    CrashLoopBackOffRule(),
]


def _pod(phase: str) -> dict:
    return {
        "metadata": {"name": "prop-pod", "namespace": "default"},
        "status": {"phase": phase},
    }


@given(snapshot=snapshot_strategy())
def test_property_output_contract_and_confidence_bounds(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()
    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
    )

    assert "root_cause" in result
    assert "confidence" in result
    assert "evidence" in result
    assert "likely_causes" in result
    assert "suggested_checks" in result
    assert "blocking" in result

    assert isinstance(result["evidence"], list)
    assert isinstance(result["likely_causes"], list)
    assert isinstance(result["suggested_checks"], list)
    assert isinstance(result["blocking"], bool)
    assert 0.0 <= float(result["confidence"]) <= 1.0


@given(
    snapshot=pvc_scheduler_snapshot_strategy(),
    rotation=st.integers(min_value=0, max_value=50),
)
def test_property_pvc_hard_blocker_survives_event_reordering(
    snapshot: K8sSnapshot, rotation: int
):
    events = copy.deepcopy(snapshot.events)
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    pod, _, context = snapshot.as_engine_input()

    result_a = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )
    result_b = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(rotated),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    for result in (result_a, result_b):
        assert result["blocking"] is True
        assert "persistentvolumeclaim" in result["root_cause"].lower()
        assert "FailedScheduling" in result["resolution"]["suppressed"]

    assert result_a["root_cause"] == result_b["root_cause"]
    assert result_a["resolution"]["winner"] == result_b["resolution"]["winner"]


@given(
    events=st.lists(event_strategy(), max_size=15),
    pvc_obj=pvc_strategy(name="test-pvc"),
)
def test_property_legacy_and_object_graph_contexts_are_equivalent(
    events: list[dict], pvc_obj: dict
):
    legacy_context = {"pvc": copy.deepcopy(pvc_obj)}
    graph_context = {"objects": {"pvc": {"test-pvc": copy.deepcopy(pvc_obj)}}}

    result_legacy = explain_failure(
        _pod("Pending"),
        copy.deepcopy(events),
        context=legacy_context,
        rules=RULES,
    )
    result_graph = explain_failure(
        _pod("Pending"),
        copy.deepcopy(events),
        context=graph_context,
        rules=RULES,
    )

    assert result_legacy["root_cause"] == result_graph["root_cause"]
    assert result_legacy["blocking"] == result_graph["blocking"]
    legacy_resolution = result_legacy.get("resolution")
    graph_resolution = result_graph.get("resolution")
    assert (legacy_resolution is None) == (graph_resolution is None)
    if legacy_resolution and graph_resolution:
        assert legacy_resolution["winner"] == graph_resolution["winner"]


@given(snapshot=snapshot_strategy())
def test_property_engine_is_deterministic_for_identical_inputs(snapshot: K8sSnapshot):
    pod1, events1, context1 = snapshot.as_engine_input()
    pod2, events2, context2 = snapshot.clone().as_engine_input()

    result_1 = explain_failure(
        pod1,
        events1,
        context=context1,
        rules=RULES,
    )
    result_2 = explain_failure(
        pod2,
        events2,
        context=context2,
        rules=RULES,
    )

    assert result_1 == result_2


@given(
    count=st.integers(min_value=1, max_value=12),
    rotation=st.integers(min_value=0, max_value=50),
)
def test_property_timestamped_failedscheduling_order_invariance(
    count: int, rotation: int
):
    events = [
        {
            "reason": "FailedScheduling",
            "message": "0/3 nodes are available",
            "lastTimestamp": f"2024-01-01T00:{i:02d}:00Z",
        }
        for i in range(count)
    ]

    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    rules = [FailedSchedulingRule()]
    result_a = explain_failure(
        _pod("Pending"),
        copy.deepcopy(events),
        context={},
        rules=rules,
    )
    result_b = explain_failure(
        _pod("Pending"),
        copy.deepcopy(rotated),
        context={},
        rules=rules,
    )

    assert result_a["root_cause"] == result_b["root_cause"]
    assert result_a.get("resolution") == result_b.get("resolution")
    assert result_a["blocking"] == result_b["blocking"]


@given(snapshot=malformed_snapshot_strategy())
def test_property_malformed_or_minimal_events_do_not_break_engine(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()
    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
    )

    assert isinstance(result, dict)
    assert isinstance(result.get("root_cause"), str)
    assert isinstance(result.get("evidence"), list)
    assert isinstance(result.get("likely_causes"), list)
    assert isinstance(result.get("suggested_checks"), list)
    assert isinstance(result.get("blocking"), bool)
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
