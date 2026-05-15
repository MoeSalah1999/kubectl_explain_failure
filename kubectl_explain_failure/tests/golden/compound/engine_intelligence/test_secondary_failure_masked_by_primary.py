import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "secondary_failure_masked_by_primary")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_secondary_failure_masked_by_primary_golden():
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

    context["pvc"] = data["pvc"]
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
    for name in expected["resolution"]["suppressed"]:
        assert name in result["resolution"]["suppressed"]

    masked = result["secondary_failure_masking"]
    assert masked["primary"] == expected["secondary_failure_masking"]["primary"]
    assert (
        masked["primary_domain"]
        == expected["secondary_failure_masking"]["primary_domain"]
    )

    masked_names = {item["name"] for item in masked["secondary"]}
    for item in expected["secondary_failure_masking"]["secondary"]:
        assert item["name"] in masked_names

    for reason in expected["secondary_failure_masking"]["recent_event_reasons"]:
        assert reason in masked["recent_event_reasons"]

    for ev in expected["evidence"]:
        assert ev in result["evidence"]
