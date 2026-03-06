import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, given, settings

from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    snapshot_strategy,
    unrelated_noise,
)


@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
@given(snapshot=snapshot_strategy())
def test_snapshot_strategy_produces_expected_shape(snapshot: K8sSnapshot):
    assert isinstance(snapshot.pod, dict)
    assert isinstance(snapshot.events, list)
    assert isinstance(snapshot.context, dict)
    assert "metadata" in snapshot.pod
    assert "status" in snapshot.pod


@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
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
