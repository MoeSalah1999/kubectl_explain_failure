import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "control_plane_flapping")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_control_plane_flapping_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])

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

    context["objects"] = {
        "pod": data.get("pods", {}),
        "deployment": data.get("deployment", {}),
        "replicaset": data.get("replicaset", {}),
        "service": data.get("service", {}),
        "endpoints": data.get("endpoints", {}),
    }

    if events:
        context["timeline"] = build_timeline(events, relative_to="last_event")

    context = normalize_context(context)
    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= expected["confidence"]
    assert result["resolution"]["winner"] == "ControlPlaneFlapping"

    for suppressed in expected.get("suppressed", []):
        assert suppressed in result["resolution"]["suppressed"]

    for evidence in expected["evidence"]:
        assert evidence in result["evidence"]

    for exp_cause, res_cause in zip(expected["causes"], result["causes"], strict=False):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)

    for obj_key, items in expected["object_evidence"].items():
        assert obj_key in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj_key]

    for likely_cause in expected.get("likely_causes", []):
        assert likely_cause in result.get("likely_causes", [])

    for suggested_check in expected.get("suggested_checks", []):
        assert suggested_check in result.get("suggested_checks", [])
