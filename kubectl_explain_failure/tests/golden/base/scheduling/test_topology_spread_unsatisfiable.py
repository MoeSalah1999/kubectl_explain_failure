import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(
    BASE_DIR, "topology_spread_unsatisfiable"
)  # fixtures are in the same folder


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_topology_spread_unsatisfiable_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    nodes = data.get("nodes")

    # Build context using engine semantics
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
    if nodes:
        context["node"] = nodes
    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # ----- Assertions -----
    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= 0.85

    # Causes
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)

    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    for obj, items in expected["object_evidence"].items():
        assert obj in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj]
