import copy

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given, strategies as st

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.base.container.crashloop_backoff import (
    CrashLoopBackOffRule,
)
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    crashloop_snapshot_strategy,
    snapshot_strategy,
)


@given(snapshot=snapshot_strategy())
def test_property_as_engine_input_returns_deep_copies(snapshot: K8sSnapshot):
    original = snapshot.clone()

    pod, events, context = snapshot.as_engine_input()

    # Mutate returned objects heavily
    pod.setdefault("metadata", {})["name"] = "mutated-pod"
    events.append({"reason": "BackOff", "message": "mutated"})
    context.setdefault("objects", {}).setdefault("configmap", {})["cm-x"] = {
        "metadata": {"name": "cm-x"}
    }

    # Snapshot instance must remain unchanged
    assert snapshot.pod == original.pod
    assert snapshot.events == original.events
    assert snapshot.context == original.context


@given(
    snapshot=crashloop_snapshot_strategy(),
    noise=st.lists(
        st.sampled_from(["FailedScheduling", "NodeNotReady", "Pulled", "Created"]),
        max_size=12,
    ),
)
def test_property_unrelated_event_noise_does_not_change_crashloop_result(
    snapshot: K8sSnapshot,
    noise: list[str],
):
    pod, events, context = snapshot.as_engine_input()

    baseline = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=[CrashLoopBackOffRule()],
    )

    noisy_events = copy.deepcopy(events) + [
        {"reason": reason, "message": f"{reason} noise"} for reason in noise
    ]

    noisy = explain_failure(
        copy.deepcopy(pod),
        noisy_events,
        context=copy.deepcopy(context),
        rules=[CrashLoopBackOffRule()],
    )

    assert noisy == baseline
