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
    crashloop_snapshot_strategy,
    snapshot_strategy,
    unrelated_noise,
)

BASE_RULES = [CrashLoopBackOffRule()]
IDEMPOTENCE_RULES = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]


@given(snapshot=snapshot_strategy())
def test_property_engine_is_idempotent_for_generated_snapshot(snapshot: K8sSnapshot):
    pod1, events1, context1 = snapshot.as_engine_input()
    pod2, events2, context2 = snapshot.clone().as_engine_input()

    result1 = explain_failure(pod1, events1, context=context1, rules=IDEMPOTENCE_RULES)
    result2 = explain_failure(pod2, events2, context=context2, rules=IDEMPOTENCE_RULES)

    assert result1 == result2


@given(snapshot=crashloop_snapshot_strategy(), noise=unrelated_noise())
def test_property_unrelated_context_noise_is_monotonic(
    snapshot: K8sSnapshot,
    noise: dict,
):
    base_pod, base_events, base_context = snapshot.as_engine_input()
    baseline = explain_failure(
        base_pod,
        base_events,
        context=base_context,
        rules=BASE_RULES,
    )

    noisy_snapshot = snapshot.inject(noise)
    noisy_pod, noisy_events, noisy_context = noisy_snapshot.as_engine_input()
    noisy = explain_failure(
        noisy_pod,
        noisy_events,
        context=noisy_context,
        rules=BASE_RULES,
    )

    assert noisy == baseline


@given(snapshot=crashloop_snapshot_strategy())
def test_property_causal_chain_structural_invariants(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()
    result = explain_failure(
        pod,
        events,
        context=context,
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
