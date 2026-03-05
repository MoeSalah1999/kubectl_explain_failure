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
from kubectl_explain_failure.rules.compound.container.crashloop_oom import (
    CrashLoopOOMKilledRule,
)

RULES = [CrashLoopOOMKilledRule(), CrashLoopBackOffRule()]


def _pod_with_oom() -> dict:
    return {
        "metadata": {"name": "oom-pod", "namespace": "default"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "lastState": {"terminated": {"reason": "OOMKilled"}},
                }
            ],
        },
    }


def _event(reason: str) -> dict:
    return {"reason": reason, "message": f"{reason} event"}


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    noise=st.lists(
        st.sampled_from(["Created", "Pulled", "Started", "NodeNotReady"]),
        max_size=10,
    ),
    rotation=st.integers(min_value=0, max_value=50),
)
def test_property_crashloop_oom_compound_is_order_stable(
    noise: list[str], rotation: int
):
    events = [_event("BackOff")] + [_event(r) for r in noise]
    rotation = rotation % len(events)
    rotated = events[rotation:] + events[:rotation]

    result_a = explain_failure(
        _pod_with_oom(),
        copy.deepcopy(events),
        context={},
        rules=RULES,
    )
    result_b = explain_failure(
        _pod_with_oom(),
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
