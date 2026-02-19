import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "node_pidpressure")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_node_pidpressure_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    node = data.get("node")

    context = build_context(
        type(
            "Args",
            (),
            {
                "pvc": None,
                "pvcs": None,
                "pv": None,
                "storageclass": None,
                "node": None,
                "serviceaccount": None,
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )

    if node:
        context["node"] = node

    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # Basic assertions
    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True

    # Rule winner
    assert result["resolution"]["winner"] == "NodePIDPressure"

    # Confidence
    assert result["confidence"] >= 0.85

    # Causes
    for i, cause in enumerate(expected["causes"]):
        assert result["causes"][i]["code"] == cause["code"]
        assert result["causes"][i]["message"] == cause["message"]
        if "blocking" in cause:
            assert result["causes"][i]["blocking"] is cause["blocking"]

    # Evidence
    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    # Object evidence
    for obj, items in expected.get("object_evidence", {}).items():
        for item in items:
            assert item in result["object_evidence"].get(obj, [])
