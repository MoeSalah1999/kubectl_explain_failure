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
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.tests.property.strategies import (
    K8sSnapshot,
    snapshot_strategy,
)


class _OverlapRuleA(FailureRule):
    name = "OverlapRuleA"
    category = "Generic"
    priority = 30

    def __init__(self, token: str):
        self.token = token

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "Overlapping signals",
            "confidence": 0.8,
            "evidence": [self.token, self.token],
            "likely_causes": [self.token, self.token],
            "suggested_checks": [self.token, self.token],
            "object_evidence": {"pod:dedupe": [self.token, self.token]},
        }


class _OverlapRuleB(FailureRule):
    name = "OverlapRuleB"
    category = "Generic"
    priority = 20

    def __init__(self, token: str):
        self.token = token

    def matches(self, pod, events, context):
        return True

    def explain(self, pod, events, context):
        return {
            "root_cause": "Overlapping signals",
            "confidence": 0.7,
            "evidence": [self.token],
            "likely_causes": [self.token],
            "suggested_checks": [self.token],
            "object_evidence": {"pod:dedupe": [self.token]},
        }


@given(snapshot=snapshot_strategy())
def test_property_explain_failure_does_not_mutate_inputs(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()
    pod_before = copy.deepcopy(pod)
    events_before = copy.deepcopy(events)
    context_before = copy.deepcopy(context)

    explain_failure(
        pod,
        events,
        context=context,
        rules=[PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()],
    )

    assert pod == pod_before
    assert events == events_before

    # Engine enriches context internally (e.g. relations/timeline).
    # We only require caller-provided keys to stay stable.
    for key, value in context_before.items():
        assert context.get(key) == value


@given(token=st.text(min_size=1, max_size=40))
def test_property_merged_output_lists_and_causes_are_deduplicated(token: str):
    pod = {
        "metadata": {"name": "dedupe-pod", "namespace": "default"},
        "status": {"phase": "Running"},
    }

    result = explain_failure(
        pod,
        events=[],
        context={},
        rules=[_OverlapRuleA(token), _OverlapRuleB(token)],
    )

    for key in ("evidence", "likely_causes", "suggested_checks"):
        values = result.get(key, [])
        assert len(values) == len(set(values))

    causes = result.get("causes", [])
    cause_ids = [(c.get("code"), c.get("message")) for c in causes]
    assert len(cause_ids) == len(set(cause_ids))

    object_evidence = result.get("object_evidence", {})
    for _, items in object_evidence.items():
        assert len(items) == len(set(items))
