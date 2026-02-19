import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "node_selector_mismatch")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_node_selector_mismatch_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    nodes = data.get("nodes", {})

    context = build_context(
        type(
            "Args",
            (),
            {
                "node": None,
                "pvc": None,
                "pvcs": None,
                "pv": None,
                "storageclass": None,
                "serviceaccount": None,
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )
    if nodes:
        context["node"] = nodes

    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] == expected["blocking"]
    assert set(result["evidence"]) == set(expected["evidence"])
    assert [c["code"] for c in result["causes"]] == [
        c["code"] for c in expected["causes"]
    ]
    assert result["object_evidence"] == expected["object_evidence"]
