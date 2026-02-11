import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "pvc_mount_failure")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_pvc_mount_failure_golden():
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
                "serviceaccount": None,
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )

    # Attach timeline explicitly
    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= 0.95

    # Verify causal chain materialization
    causes = result["causes"]
    assert causes[0]["code"] == "PVC_BOUND"
    assert causes[0].get("blocking", False) is False
    assert causes[1]["code"] == "MOUNT_FAILED"
    assert causes[1]["blocking"] is True

    # Verify object evidence
    assert "pvc:test-pvc" in result["object_evidence"]
    assert "pod:test-pod" in result["object_evidence"]

    # Optional: verify evidence messages
    evidence = result["evidence"]
    assert any("FailedMount" in e or "MountVolume" in e for e in evidence)
