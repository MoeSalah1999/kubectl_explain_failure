import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline


BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "crashloop_liveness")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_crashloop_liveness_probe_compound_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])

    # Build context explicitly (engine-style, consistent with OOM test)
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

    # Attach timeline (required by compound rule)
    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # -------------------------------------------------
    # Root cause validation
    # -------------------------------------------------
    assert result["root_cause"] == expected["root_cause"]

    # -------------------------------------------------
    # Blocking validation
    # -------------------------------------------------
    assert result["blocking"] is True

    # -------------------------------------------------
    # Confidence validation
    # -------------------------------------------------
    assert result["confidence"] >= expected["confidence_min"]

    # -------------------------------------------------
    # Causal chain validation (engine materializes list of dicts)
    # -------------------------------------------------
    causes = result["causes"]

    assert causes[0]["code"] == expected["causes"][0]["code"]
    assert causes[0]["blocking"] is True

    assert causes[1]["code"] == expected["causes"][1]["code"]
