import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "suppressed_signal_explanation")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_suppressed_signal_explanation_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    objects = data.get("objects", {})

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

    context["objects"] = objects
    context["serviceaccount"] = {"metadata": {"name": "default"}}
    context["secret"] = {"metadata": {"name": "registry-creds"}}

    if events:
        context["timeline"] = build_timeline(events, relative_to="last_event")

    context = normalize_context(context)
    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= expected["confidence"]

    assert result["resolution"]["winner"] == expected["resolution"]["winner"]
    assert (
        result["resolution"]["explained_by"] == expected["resolution"]["explained_by"]
    )
    assert result["resolution"]["reason"] == expected["resolution"]["reason"]

    for suppressed in expected["resolution"]["suppressed"]:
        assert suppressed in result["resolution"]["suppressed"]

    detail_names = {
        item["name"] for item in result["resolution"].get("suppressed_details", [])
    }
    for suppressed in expected["resolution"]["suppressed"]:
        assert suppressed in detail_names

    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    explanation = result["suppressed_signal_explanation"]
    assert explanation["winner"] == expected["suppressed_signal_explanation"]["winner"]
    assert (
        explanation["winner_root_cause"]
        == expected["suppressed_signal_explanation"]["winner_root_cause"]
    )

    for suppressed in expected["suppressed_signal_explanation"]["suppressed"]:
        assert suppressed in explanation["suppressed"]

    for reason in expected["suppressed_signal_explanation"]["recent_event_reasons"]:
        assert reason in explanation["recent_event_reasons"]
