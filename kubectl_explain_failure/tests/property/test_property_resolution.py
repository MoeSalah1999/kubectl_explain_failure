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
from kubectl_explain_failure.rules.compound.container.crashloop_oom import (
    CrashLoopOOMKilledRule,
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
        "message": st.text(max_size=100),
    }
)


@settings(max_examples=160, suppress_health_check=[HealthCheck.too_slow])
@given(
    phase=st.sampled_from(["Pending", "Running", "Failed"]),
    events=st.lists(event_strategy, max_size=20),
    pvc_present=st.booleans(),
    pvc_phase=st.sampled_from(["Pending", "Bound"]),
    oom=st.booleans(),
)
def test_property_resolution_and_causes_integrity(
    phase: str,
    events: list[dict],
    pvc_present: bool,
    pvc_phase: str,
    oom: bool,
):
    context = {"pvc": _pvc(pvc_phase)} if pvc_present else {}

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
