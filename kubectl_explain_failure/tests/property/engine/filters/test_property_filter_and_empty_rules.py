import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given

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


@given(snapshot=snapshot_strategy())
def test_property_unmatched_enabled_category_returns_unknown(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
        enabled_categories=["__NON_EXISTENT_CATEGORY__"],
    )

    assert result["root_cause"] == "Unknown"
    assert float(result["confidence"]) == 0.0
    assert result["blocking"] is False
    assert result["evidence"] == []
    assert result["likely_causes"] == []
    assert result["suggested_checks"] == []
    assert "resolution" not in result


@given(snapshot=snapshot_strategy())
def test_property_empty_disabled_categories_is_equivalent_to_no_filter(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    result_none = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
        disabled_categories=None,
    )
    result_empty = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
        disabled_categories=[],
    )

    assert result_empty == result_none
