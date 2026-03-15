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
    snapshot_strategy,
)

RULES = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]
KNOWN_CATEGORIES = {"PersistentVolumeClaim", "Scheduling", "Container"}
UNKNOWN_CATEGORIES = ["__UNKNOWN_A__", "__UNKNOWN_B__", "__UNKNOWN_C__"]


@given(
    snapshot=snapshot_strategy(),
    enabled_unknown=st.lists(
        st.sampled_from(UNKNOWN_CATEGORIES), min_size=1, unique=True, max_size=3
    ),
)
def test_property_enabling_only_unknown_categories_returns_unknown(
    snapshot: K8sSnapshot,
    enabled_unknown: list[str],
):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
        enabled_categories=enabled_unknown,
    )

    assert result["root_cause"] == "Unknown"
    assert float(result["confidence"]) == 0.0
    assert result["blocking"] is False
    assert result["evidence"] == []
    assert result["likely_causes"] == []
    assert result["suggested_checks"] == []
    assert "resolution" not in result


@given(snapshot=snapshot_strategy())
def test_property_disabling_all_known_categories_returns_unknown(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
        disabled_categories=sorted(KNOWN_CATEGORIES),
    )

    assert result["root_cause"] == "Unknown"
    assert float(result["confidence"]) == 0.0
    assert result["blocking"] is False
    assert result["evidence"] == []
    assert result["likely_causes"] == []
    assert result["suggested_checks"] == []
    assert "resolution" not in result
