import copy
import itertools

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
    snapshot_strategy,
    unrelated_noise,
)


def _merge_noise(a: dict, b: dict) -> dict:
    merged = {"objects": {}, "events": []}

    for src in (a, b):
        if isinstance(src.get("events"), list):
            merged["events"].extend(copy.deepcopy(src["events"]))

        objects = src.get("objects", {})
        if isinstance(objects, dict):
            for kind, mapping in objects.items():
                if not isinstance(mapping, dict):
                    continue
                merged["objects"].setdefault(kind, {})
                merged["objects"][kind].update(copy.deepcopy(mapping))

    if not merged["events"]:
        merged.pop("events")
    if not merged["objects"]:
        merged.pop("objects")

    return merged


def _result_digest(result: dict) -> dict:
    resolution = result.get("resolution")
    digest = {
        "root_cause": result.get("root_cause"),
        "blocking": result.get("blocking"),
        "confidence": float(result.get("confidence", 0.0)),
    }
    if resolution:
        digest["winner"] = resolution.get("winner")
        digest["suppressed"] = tuple(sorted(resolution.get("suppressed", [])))
    else:
        digest["winner"] = None
        digest["suppressed"] = ()
    return digest


@given(snapshot=snapshot_strategy(), noise_a=unrelated_noise(), noise_b=unrelated_noise())
def test_property_inject_is_associative_for_noise_merges(
    snapshot: K8sSnapshot,
    noise_a: dict,
    noise_b: dict,
):
    seq = snapshot.inject(noise_a).inject(noise_b)
    merged_once = snapshot.inject(_merge_noise(noise_a, noise_b))

    assert seq.pod == merged_once.pod
    assert seq.events == merged_once.events
    assert seq.context == merged_once.context


@given(snapshot=snapshot_strategy())
def test_property_rule_permutation_does_not_change_decision(snapshot: K8sSnapshot):
    pod, events, context = snapshot.as_engine_input()

    base_rules = [PVCNotBoundRule(), FailedSchedulingRule(), CrashLoopBackOffRule()]
    permutations = list(itertools.permutations(base_rules))

    digests = []
    for perm in permutations:
        result = explain_failure(
            copy.deepcopy(pod),
            copy.deepcopy(events),
            context=copy.deepcopy(context),
            rules=list(perm),
        )
        digests.append(_result_digest(result))

    assert all(d == digests[0] for d in digests)
