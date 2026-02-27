import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "limitrange_violation")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_limitrange_violation_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])

    # Build baseline context (same structure as other golden tests)
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

    # Inject noise objects to improve data completeness
    context["node"] = {"node1": {"metadata": {"name": "node1"}}}
    context["pvc"] = {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}}
    context["pv"] = {"metadata": {"name": "pv1"}}
    context["storageclass"] = {"metadata": {"name": "sc1"}}
    context["serviceaccount"] = {"metadata": {"name": "default"}}
    context["secret"] = {"metadata": {"name": "mysecret"}}

    if events:
        context["timeline"] = build_timeline(events)

    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # Root cause
    assert result["root_cause"] == expected["root_cause"]

    # Blocking
    assert result["blocking"] is True

    # Confidence remains high
    assert result["confidence"] >= 0.80

    # Evidence
    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    # Causes
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)

    # Object evidence
    assert "object_evidence" in result
    for obj_key, items in expected["object_evidence"].items():
        assert obj_key in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj_key]
