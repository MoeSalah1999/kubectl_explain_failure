import os
import json

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context, get_default_rules
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "rapid_restart_escalation")

def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)

def test_rapid_restart_escalation_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data
    events = data.get("events", [])

    # Build context explicitly
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

    # Attach timeline explicitly (required by compound rule)
    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # Core root cause / blocking check
    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= 0.90

    # Verify causal chain materialization
    causes = result["causes"]
    assert causes[0]["code"] == "RAPID_RESTARTS"
    assert causes[0]["blocking"] is True

    # Verify object evidence matches pod
    pod_name = pod.get("metadata", {}).get("name", "<unknown>")
    assert f"pod:{pod_name}" in result.get("object_evidence", {})
