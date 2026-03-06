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


def _pod(name: str, phase: str) -> dict:
    return {
        "metadata": {"name": name, "namespace": "default"},
        "status": {"phase": phase},
    }


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
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


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running"]),
    backoff_count=st.integers(min_value=1, max_value=12),
    noise=st.lists(st.sampled_from(["Pulled", "Created", "Started"]), max_size=12),
)
def test_property_single_deterministic_rule_short_circuits_aggregation(
    phase: str,
    backoff_count: int,
    noise: list[str],
):
    events = (
        [{"reason": "BackOff", "message": "container restart backoff"}] * backoff_count
        + [{"reason": r, "message": f"{r} event"} for r in noise]
    )

    result = explain_failure(
        _pod("deterministic-pod", phase),
        events=copy.deepcopy(events),
        context={},
        rules=[CrashLoopBackOffRule()],
    )

    assert result["resolution"]["winner"] == "CrashLoopBackOff"
    assert result["resolution"]["reason"] == "Deterministic rule matched with high confidence"
    assert "crashloopbackoff" in result["root_cause"].lower()
    assert float(result["confidence"]) == pytest.approx(0.92, abs=1e-9)
    assert result["blocking"] is True
    assert isinstance(result.get("causes"), list)
    assert len(result["causes"]) >= 1
