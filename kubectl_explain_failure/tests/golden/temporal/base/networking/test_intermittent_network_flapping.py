import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "intermittent_network_flapping")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_intermittent_network_flapping_golden():
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

    # Noise objects (data completeness boost)
    context["node"] = {"node1": {"metadata": {"name": "node1"}}}
    context["pvc"] = {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}}
    context["pv"] = {"metadata": {"name": "pv1"}}
    context["storageclass"] = {"metadata": {"name": "sc1"}}
    context["serviceaccount"] = {"metadata": {"name": "default"}}
    context["secret"] = {"metadata": {"name": "mysecret"}}

    if events:
        context["timeline"] = build_timeline(events, relative_to="last_event")

    context = normalize_context(context)
    result = explain_failure(pod, events, context=context)

    # Root cause
    assert result["root_cause"] == expected["root_cause"]

    # Blocking
    assert result["blocking"] is False

    # Confidence
    assert result["confidence"] >= 0.75

    # Evidence
    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    # Causes
    for exp_cause, res_cause in zip(expected["causes"], result["causes"], strict=False):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)

    # Object evidence validation (if present)
    if "object_evidence" in expected:
        assert "object_evidence" in result
        for obj, items in expected["object_evidence"].items():
            assert obj in result["object_evidence"]
            for item in items:
                assert item in result["object_evidence"][obj]

    # Likely causes
    for lc in expected.get("likely_causes", []):
        assert lc in result.get("likely_causes", [])

    # Suggested checks
    for sc in expected.get("suggested_checks", []):
        assert sc in result.get("suggested_checks", [])
