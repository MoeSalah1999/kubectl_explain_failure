import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import (
    explain_failure,
    normalize_context,
)
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "pvc_bound_node_diskpressure_mount")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_pvc_bound_node_diskpressure_mount_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    raw_context = data.get("context", {})

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

    # Inject structured objects directly (bypass file loading)
    if "pvc" in raw_context:
        context["pvc"] = raw_context["pvc"]

    if "node" in raw_context:
        context["node"] = raw_context["node"]

    # Attach timeline (required by rule)
    context["timeline"] = build_timeline(events)

    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # ---- Root cause ----
    assert result["root_cause"] == expected["root_cause"]

    # ---- Blocking semantics ----
    assert result["blocking"] is True

    # ---- Confidence threshold ----
    assert result["confidence"] >= 0.78

    # ---- Evidence ----
    assert result["evidence"] == expected["evidence"]

    # ---- Causal chain materialization ----
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)


    # ---- Object evidence passthrough ----
    assert result["object_evidence"] == expected["object_evidence"]
