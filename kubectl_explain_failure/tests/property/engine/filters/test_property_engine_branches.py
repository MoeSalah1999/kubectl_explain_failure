import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given, strategies as st

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
    crashloop_snapshot_strategy,
    pvc_scheduler_snapshot_strategy,
)


def _pod(name: str, phase: str) -> dict:
    return {
        "metadata": {"name": name, "namespace": "default"},
        "status": {"phase": phase},
    }


@given(
    pod_name=st.text(min_size=1, max_size=24),
    phase=st.sampled_from(["Pending", "Running", "Failed", "Unknown"]),
)
def test_property_no_signals_returns_unknown(
    pod_name: str,
    phase: str,
):
    rules = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]

    result = explain_failure(
        _pod(pod_name, phase),
        events=[],
        context={},
        rules=rules,
    )

    assert result["root_cause"] == "Unknown"
    assert float(result["confidence"]) == 0.0
    assert result["blocking"] is False
    assert result["evidence"] == []
    assert result["likely_causes"] == []
    assert result["suggested_checks"] == []
    assert "resolution" not in result


@given(snapshot=crashloop_snapshot_strategy())
def test_property_single_deterministic_rule_short_circuits_aggregation(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events=copy.deepcopy(events),
        context=context,
        rules=[CrashLoopBackOffRule()],
    )

    assert result["resolution"]["winner"] == "CrashLoopBackOff"
    assert (
        result["resolution"]["reason"]
        == "Deterministic rule matched with high confidence"
    )
    assert "crashloopbackoff" in result["root_cause"].lower()
    assert float(result["confidence"]) == pytest.approx(0.92, abs=1e-9)
    assert result["blocking"] is True
    assert isinstance(result.get("causes"), list)
    assert len(result["causes"]) >= 1


@given(snapshot=pvc_scheduler_snapshot_strategy(), rotation=st.integers(min_value=0, max_value=50))
def test_property_enabled_categories_restricts_to_scheduling(
    snapshot: K8sSnapshot,
    rotation: int,
):
    events = copy.deepcopy(snapshot.events)
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    pod = copy.deepcopy(snapshot.pod)
    context = copy.deepcopy(snapshot.context)
    rules = [PVCNotBoundRule(), FailedSchedulingRule()]

    result_a = explain_failure(
        copy.deepcopy(pod),
        events=copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=rules,
        enabled_categories=["Scheduling"],
    )
    result_b = explain_failure(
        copy.deepcopy(pod),
        events=copy.deepcopy(rotated),
        context=copy.deepcopy(context),
        rules=rules,
        enabled_categories=["Scheduling"],
    )

    for result in (result_a, result_b):
        assert "persistentvolumeclaim" not in result["root_cause"].lower()
        assert result["resolution"]["winner"] == "FailedScheduling"


@given(snapshot=pvc_scheduler_snapshot_strategy(), rotation=st.integers(min_value=0, max_value=50))
def test_property_disabled_categories_excludes_pvc_rules(
    snapshot: K8sSnapshot,
    rotation: int,
):
    events = copy.deepcopy(snapshot.events)
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    pod = copy.deepcopy(snapshot.pod)
    context = copy.deepcopy(snapshot.context)
    rules = [PVCNotBoundRule(), FailedSchedulingRule()]

    result_a = explain_failure(
        copy.deepcopy(pod),
        events=copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=rules,
        disabled_categories=["PersistentVolumeClaim"],
    )
    result_b = explain_failure(
        copy.deepcopy(pod),
        events=copy.deepcopy(rotated),
        context=copy.deepcopy(context),
        rules=rules,
        disabled_categories=["PersistentVolumeClaim"],
    )

    for result in (result_a, result_b):
        assert "persistentvolumeclaim" not in result["root_cause"].lower()
        assert result["resolution"]["winner"] == "FailedScheduling"
