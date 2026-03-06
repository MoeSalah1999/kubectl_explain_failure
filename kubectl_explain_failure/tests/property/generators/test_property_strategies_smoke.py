import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given

from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    crashloop_snapshot_strategy,
    malformed_snapshot_strategy,
    pvc_scheduler_snapshot_strategy,
    snapshot_strategy,
    unrelated_noise,
)


@given(snapshot=snapshot_strategy())
def test_snapshot_strategy_produces_expected_shape(snapshot: K8sSnapshot):
    assert isinstance(snapshot.pod, dict)
    assert isinstance(snapshot.events, list)
    assert isinstance(snapshot.context, dict)
    assert "metadata" in snapshot.pod
    assert "status" in snapshot.pod


@given(snapshot=snapshot_strategy(), noise=unrelated_noise())
def test_snapshot_clone_and_inject_are_non_destructive(
    snapshot: K8sSnapshot,
    noise: dict,
):
    cloned = snapshot.clone()
    injected = snapshot.inject(noise)

    assert cloned is not snapshot
    assert injected is not snapshot
    assert injected.pod == snapshot.pod

    original_count = len(snapshot.context.get("objects", {}))
    injected_count = len(injected.context.get("objects", {}))
    assert injected_count >= original_count


@given(snapshot=crashloop_snapshot_strategy())
def test_crashloop_snapshot_strategy_has_backoff_signal(snapshot: K8sSnapshot):
    reasons = [e.get("reason") for e in snapshot.events]
    assert "BackOff" in reasons


@given(snapshot=pvc_scheduler_snapshot_strategy())
def test_pvc_scheduler_snapshot_strategy_has_pending_pvc_context(snapshot: K8sSnapshot):
    assert snapshot.context.get("pvc_unbound") is True
    assert isinstance(snapshot.context.get("blocking_pvc"), dict)


@given(snapshot=malformed_snapshot_strategy())
def test_malformed_snapshot_strategy_shape(snapshot: K8sSnapshot):
    assert isinstance(snapshot.pod, dict)
    assert isinstance(snapshot.events, list)
    assert isinstance(snapshot.context, dict)
