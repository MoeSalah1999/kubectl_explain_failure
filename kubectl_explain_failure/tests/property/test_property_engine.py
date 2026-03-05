import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, given, settings, strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.container.crashloop_backoff import (
    CrashLoopBackOffRule,
)
from kubectl_explain_failure.rules.base.scheduling.failed_scheduling import (
    FailedSchedulingRule,
)
from kubectl_explain_failure.rules.base.storage.pvc_not_bound import PVCNotBoundRule

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


def _pvc(phase: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "test-pvc"},
        "status": {"phase": phase},
    }


event_strategy = st.fixed_dictionaries(
    {
        "reason": st.sampled_from(
            [
                "FailedScheduling",
                "BackOff",
                "FailedMount",
                "Pulled",
                "Created",
                "Started",
                "NodeNotReady",
            ]
        ),
        "message": st.text(max_size=120),
    }
)


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running", "Failed", "Unknown"]),
    events=st.lists(event_strategy, max_size=20),
)
def test_property_output_contract_and_confidence_bounds(phase: str, events: list[dict]):
    result = explain_failure(
        _pod(phase),
        copy.deepcopy(events),
        context={},
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


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    events=st.lists(
        st.fixed_dictionaries(
            {
                "reason": st.sampled_from(
                    ["FailedScheduling", "NodeNotReady", "TaintBasedEviction"]
                ),
                "message": st.text(max_size=80),
            }
        ),
        min_size=1,
        max_size=20,
    ),
    rotation=st.integers(min_value=0, max_value=50),
)
def test_property_pvc_hard_blocker_survives_event_reordering(
    events: list[dict], rotation: int
):
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    result_a = explain_failure(
        _pod("Pending"),
        copy.deepcopy(events),
        context={"pvc": _pvc("Pending")},
        rules=RULES,
    )
    result_b = explain_failure(
        _pod("Pending"),
        copy.deepcopy(rotated),
        context={"pvc": _pvc("Pending")},
        rules=RULES,
    )

    for result in (result_a, result_b):
        assert result["blocking"] is True
        assert "persistentvolumeclaim" in result["root_cause"].lower()
        assert "FailedScheduling" in result["resolution"]["suppressed"]

    assert result_a["root_cause"] == result_b["root_cause"]
    assert result_a["resolution"]["winner"] == result_b["resolution"]["winner"]


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    events=st.lists(event_strategy, max_size=15),
    pvc_phase=st.sampled_from(["Pending", "Bound"]),
)
def test_property_legacy_and_object_graph_contexts_are_equivalent(
    events: list[dict], pvc_phase: str
):
    pvc_obj = _pvc(pvc_phase)
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


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running"]),
    events=st.lists(event_strategy, max_size=20),
    pvc_present=st.booleans(),
    pvc_phase=st.sampled_from(["Pending", "Bound"]),
)
def test_property_engine_is_deterministic_for_identical_inputs(
    phase: str, events: list[dict], pvc_present: bool, pvc_phase: str
):
    context = {"pvc": _pvc(pvc_phase)} if pvc_present else {}

    result_1 = explain_failure(
        _pod(phase),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )
    result_2 = explain_failure(
        _pod(phase),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    assert result_1 == result_2

@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
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


minimal_event_strategy = st.fixed_dictionaries(
    {},
    optional={
        "reason": st.one_of(
            st.none(),
            st.sampled_from(["BackOff", "FailedScheduling", "FailedMount"]),
        ),
        "message": st.one_of(st.none(), st.text(max_size=120)),
        "lastTimestamp": st.one_of(
            st.none(),
            st.sampled_from(
                [
                    "2024-01-01T00:00:00Z",
                    "not-a-timestamp",
                    "",
                ]
            ),
        ),
        "source": st.one_of(
            st.none(),
            st.text(max_size=20),
            st.fixed_dictionaries(
                {"component": st.text(max_size=20)}
            ),
        ),
    },
)


