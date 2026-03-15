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
from kubectl_explain_failure.rules.compound.container.crashloop_oom import (
    CrashLoopOOMKilledRule,
)
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    crashloop_oom_snapshot_strategy,
)

RULES = [CrashLoopOOMKilledRule(), CrashLoopBackOffRule()]


@given(
    snapshot=crashloop_oom_snapshot_strategy(),
    rotation=st.integers(min_value=0, max_value=50),
)
def test_property_crashloop_oom_compound_is_order_stable(
    snapshot: K8sSnapshot,
    rotation: int,
):
    events = copy.deepcopy(snapshot.events)
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    pod = copy.deepcopy(snapshot.pod)

    result_a = explain_failure(
        pod,
        copy.deepcopy(events),
        context={},
        rules=RULES,
    )
    result_b = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(rotated),
        context={},
        rules=RULES,
    )

    for result in (result_a, result_b):
        assert "oomkilled" in result["root_cause"].lower()
        assert result["blocking"] is True
        assert result["resolution"]["winner"] == "CrashLoopOOMKilled"
        assert "CrashLoopBackOff" in result["resolution"]["suppressed"]

    assert result_a["root_cause"] == result_b["root_cause"]
    assert result_a["resolution"] == result_b["resolution"]
