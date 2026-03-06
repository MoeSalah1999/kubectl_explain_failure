import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given

from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    snapshot_strategy,
    unrelated_noise,
)


@given(snapshot=snapshot_strategy(), noise=unrelated_noise())
def test_property_snapshot_inject_does_not_mutate_original(
    snapshot: K8sSnapshot,
    noise: dict,
):
    before = snapshot.clone()

    injected = snapshot.inject(noise)

    assert snapshot.pod == before.pod
    assert snapshot.events == before.events
    assert snapshot.context == before.context

    expected_events = len(before.events) + len(noise.get("events", []))
    assert len(injected.events) == expected_events


@given(snapshot=snapshot_strategy())
def test_property_as_engine_input_returns_deep_copies(snapshot: K8sSnapshot):
    baseline = snapshot.clone()
    pod, events, context = snapshot.as_engine_input()

    pod.setdefault("metadata", {})["name"] = "mutated-name"
    events.append({"reason": "InjectedMutation", "message": "mutation"})
    context.setdefault("objects", {}).setdefault("configmap", {})["m"] = {
        "metadata": {"name": "m"}
    }

    assert snapshot.pod == baseline.pod
    assert snapshot.events == baseline.events
    assert snapshot.context == baseline.context
