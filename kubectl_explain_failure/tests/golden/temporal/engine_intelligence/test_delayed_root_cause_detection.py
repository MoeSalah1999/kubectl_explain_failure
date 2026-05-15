import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "delayed_root_cause_detection")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_delayed_root_cause_detection_golden():
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

    context["node"] = {"node1": {"metadata": {"name": "node1"}}}
    context["pvc"] = {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}}
    context["pv"] = {"metadata": {"name": "pv1"}}
    context["storageclass"] = {"metadata": {"name": "sc1"}}
    context["serviceaccount"] = {"metadata": {"name": "default"}}
    context["secret"] = {"metadata": {"name": "registry-secret"}}
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

    delayed = result["delayed_root_cause_detection"]
    assert delayed["winner"] == expected["delayed_root_cause_detection"]["winner"]
    assert (
        delayed["winner_root_cause"]
        == expected["delayed_root_cause_detection"]["winner_root_cause"]
    )
    assert (
        delayed["first_symptom_reason"]
        == expected["delayed_root_cause_detection"]["first_symptom_reason"]
    )
    assert (
        delayed["decisive_root_cause_reason"]
        == expected["delayed_root_cause_detection"]["decisive_root_cause_reason"]
    )
    assert (
        delayed["delay_minutes"]
        >= expected["delayed_root_cause_detection"]["delay_minutes"]
    )
    assert (
        delayed["earlier_symptom_count"]
        == expected["delayed_root_cause_detection"]["earlier_symptom_count"]
    )

    for exp_cause in expected["causes"]:
        assert exp_cause in result["causes"]

    for ev in expected["evidence"]:
        assert ev in result["evidence"]
