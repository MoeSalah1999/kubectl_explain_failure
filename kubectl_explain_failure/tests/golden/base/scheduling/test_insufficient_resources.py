import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "insufficient_resources")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_insufficient_resources_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    nodes = data.get("nodes")

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

    if nodes:
        context["node"] = nodes

    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # Root cause check
    assert result["root_cause"] == expected["root_cause"]
    # Winner rule check
    assert result["resolution"]["winner"] == "InsufficientResources"
    # Blocking & confidence
    assert result["blocking"] is True
    assert result["confidence"] >= 0.85

    # Causes verification
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        if "blocking" in exp_cause:
            assert res_cause.get("blocking") is True

    # Evidence verification
    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    # Object evidence verification
    for obj, messages in expected["object_evidence"].items():
        assert obj in result["object_evidence"]
        for msg in messages:
            assert msg in result["object_evidence"][obj]
