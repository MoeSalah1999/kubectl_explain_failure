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
from kubectl_explain_failure.rules.compound.container.crashloop_oom import (
    CrashLoopOOMKilledRule,
)
from kubectl_explain_failure.tests.property.strategies import (
    event_strategy,
    pvc_strategy,
)

RULES = [
    PVCNotBoundRule(),
    FailedSchedulingRule(),
    CrashLoopBackOffRule(),
    CrashLoopOOMKilledRule(),
]


def _pod(phase: str, oom: bool) -> dict:
    pod = {
        "metadata": {"name": "prop-pod", "namespace": "default"},
        "status": {"phase": phase},
    }
    if oom:
        pod["status"]["containerStatuses"] = [
            {
                "name": "app",
                "lastState": {"terminated": {"reason": "OOMKilled"}},
            }
        ]
    return pod


@given(
    phase=st.sampled_from(["Pending", "Running", "Failed"]),
    events=st.lists(event_strategy(), max_size=20),
    pvc_present=st.booleans(),
    pvc_obj=pvc_strategy(name="test-pvc"),
    oom=st.booleans(),
)
def test_property_resolution_and_causes_integrity(
    phase: str,
    events: list[dict],
    pvc_present: bool,
    pvc_obj: dict,
    oom: bool,
):
    context = {"pvc": copy.deepcopy(pvc_obj)} if pvc_present else {}

    result = explain_failure(
        _pod(phase, oom),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    assert isinstance(result.get("root_cause"), str)
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
    assert isinstance(result.get("blocking"), bool)

    causes = result.get("causes", [])
    assert isinstance(causes, list)
    for cause in causes:
        assert isinstance(cause.get("code"), str)
        assert isinstance(cause.get("message"), str)

    resolution = result.get("resolution")
    if resolution is not None:
        winner = resolution.get("winner")
        suppressed = resolution.get("suppressed", [])
        assert isinstance(winner, str)
        assert winner
        assert isinstance(suppressed, list)
        assert len(suppressed) == len(set(suppressed))
        assert winner not in suppressed

    if result.get("blocking") and causes:
        assert any(bool(c.get("blocking")) for c in causes)
