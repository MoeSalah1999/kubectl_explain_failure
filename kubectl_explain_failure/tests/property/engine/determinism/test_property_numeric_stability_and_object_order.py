import copy
import math

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
    malformed_snapshot_strategy,
    snapshot_strategy,
)

RULES = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]


def _reversed_object_graph(objects: dict) -> dict:
    reversed_graph: dict = {}
    for kind, mapping in reversed(list(objects.items())):
        if isinstance(mapping, dict):
            reversed_graph[kind] = dict(reversed(list(mapping.items())))
        else:
            reversed_graph[kind] = mapping
    return reversed_graph


@given(snapshot=snapshot_strategy())
def test_property_object_graph_iteration_order_does_not_change_decision(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    baseline = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=copy.deepcopy(context),
        rules=RULES,
    )

    reordered_context = copy.deepcopy(context)
    objects = reordered_context.get("objects", {})
    if isinstance(objects, dict):
        reordered_context["objects"] = _reversed_object_graph(objects)

    reordered = explain_failure(
        copy.deepcopy(pod),
        copy.deepcopy(events),
        context=reordered_context,
        rules=RULES,
    )

    assert reordered["root_cause"] == baseline["root_cause"]
    assert reordered["blocking"] == baseline["blocking"]

    baseline_resolution = baseline.get("resolution")
    reordered_resolution = reordered.get("resolution")
    assert (baseline_resolution is None) == (reordered_resolution is None)
    if baseline_resolution and reordered_resolution:
        assert reordered_resolution.get("winner") == baseline_resolution.get("winner")


@given(snapshot=malformed_snapshot_strategy())
def test_property_malformed_inputs_keep_confidence_finite_and_normalized(
    snapshot: K8sSnapshot,
):
    pod, events, context = snapshot.as_engine_input()

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=RULES,
    )

    confidence = float(result.get("confidence", 0.0))
    assert math.isfinite(confidence)
    assert not math.isnan(confidence)
    assert 0.0 <= confidence <= 1.0
