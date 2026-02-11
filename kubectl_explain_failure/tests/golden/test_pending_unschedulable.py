import json
import os

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.rules.pending_unschedulable import PendingUnschedulableRule
from kubectl_explain_failure.timeline import build_timeline

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "pending_unschedulable")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_pending_unschedulable_rule():
    pod = load_fixture("input.json")
    events = pod.pop("events", [])
    context = {"timeline": build_timeline(events)}

    result = explain_failure(
        pod, events, context=context, rules=[PendingUnschedulableRule()]
    )

    expected = load_fixture("expected.json")
    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] == expected["blocking"]
    assert set(result.get("evidence", [])) == set(expected.get("evidence", []))
    assert result.get("object_evidence") == expected.get("object_evidence")
