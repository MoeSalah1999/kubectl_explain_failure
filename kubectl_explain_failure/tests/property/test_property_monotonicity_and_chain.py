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


BASE_RULES = [CrashLoopBackOffRule()]


def _pod_running() -> dict:
    return {
        "metadata": {"name": "mono-pod", "namespace": "default"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                }
            ],
        },
    }


def _base_events(backoff_count: int) -> list[dict]:
    return [
        {"reason": "BackOff", "message": "restart backoff"}
        for _ in range(backoff_count)
    ]


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(
    backoff_count=st.integers(min_value=1, max_value=10),
    noise_kinds=st.lists(
        st.sampled_from(["configmap", "secret", "serviceaccount", "node", "pv"]),
        max_size=12,
    ),
)
def test_property_unrelated_context_noise_is_monotonic(
    backoff_count: int,
    noise_kinds: list[str],
):
    pod = _pod_running()
    events = _base_events(backoff_count)

    baseline = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context={},
        rules=BASE_RULES,
    )

    noisy_context = {"objects": {}}
    for i, kind in enumerate(noise_kinds):
        noisy_context["objects"].setdefault(kind, {})[f"{kind}-{i}"] = {
            "metadata": {"name": f"{kind}-{i}"}
        }

    noisy = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=noisy_context,
        rules=BASE_RULES,
    )

    assert noisy == baseline


@settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
@given(backoff_count=st.integers(min_value=1, max_value=12))
def test_property_causal_chain_structural_invariants(backoff_count: int):
    result = explain_failure(
        _pod_running(),
        _base_events(backoff_count),
        context={},
        rules=BASE_RULES,
    )

    causes = result.get("causes", [])

    # Non-trivial causal chain expected for CrashLoopBackOffRule
    assert len(causes) >= 2

    # Unique causes by semantic identity
    cause_ids = [(c.get("code"), c.get("message")) for c in causes]
    assert len(cause_ids) == len(set(cause_ids))

    # Structural quality
    assert all(isinstance(c.get("code"), str) and c.get("code") for c in causes)
    assert all(isinstance(c.get("message"), str) and c.get("message") for c in causes)

    # Blocking invariants
    blocking_count = sum(1 for c in causes if c.get("blocking") is True)
    assert blocking_count <= 1
    if result.get("blocking") is True:
        assert blocking_count == 1
