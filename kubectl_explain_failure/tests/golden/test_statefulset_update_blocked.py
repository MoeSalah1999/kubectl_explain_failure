import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "statefulset_update_blocked")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_statefulset_update_blocked_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    statefulset = data.get("statefulsets")

    # Build context with minimal dummy objects
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

    # Inject actual StatefulSet under test
    if statefulset:
        context["objects"]["statefulset"] = statefulset

    # Build timeline if events exist
    if events:
        context["timeline"] = build_timeline(events)

    # Add minimal node / PVC objects to satisfy engine normalization
    context["node"] = {"node1": {"metadata": {"name": "node1"}}}
    context["pvc"] = {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}}
    

    # Normalize context
    context = normalize_context(context)

    # Run engine
    result = explain_failure(pod, events, context=context)

    # Root cause
    assert result["root_cause"] == expected["root_cause"]

    # Blocking check
    assert result["blocking"] is True

    # Confidence check
    assert result["confidence"] >= 0.85

    # Evidence check
    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    # Causes check
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)

    # Object evidence check
    for obj, items in expected["object_evidence"].items():
        assert obj in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj]
