import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "serviceaccount_missing")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_serviceaccount_missing_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])

    # Build context explicitly (engine-style)
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
                "serviceaccount": {},
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )

    # Attach timeline explicitly (rule requires it)
    context["timeline"] = build_timeline(events)
    # Inject objects correctly
    context["objects"] = {
        "serviceaccount": {"default": {"metadata": {"name": "default"}}}
    }
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= 0.95

    # Verify causal chain materialization
    causes = result.get("causes", [])
    assert causes[0]["code"] == "SERVICE_ACCOUNT_MISSING"
    assert causes[0]["blocking"] is True
