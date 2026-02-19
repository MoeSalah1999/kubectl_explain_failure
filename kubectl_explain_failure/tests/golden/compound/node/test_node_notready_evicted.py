import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "node_notready_evicted")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_node_notready_evicted_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    node = data.get("node")

    # ---------------------------------
    # Build context (engine-style, no file loading)
    # ---------------------------------
    context = build_context(
        type(
            "Args",
            (),
            {
                "pvc": None,
                "pvcs": None,
                "pv": None,
                "storageclass": None,
                "node": None,  # IMPORTANT: must be None (not dict)
                "serviceaccount": None,
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )

    # Inject node object directly (fixture already loaded)
    if node:
        context["node"] = node

    # Attach timeline explicitly (compound rule requires it)
    context["timeline"] = build_timeline(events)

    # Normalize object graph
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # ---------------------------------
    # Root cause contract
    # ---------------------------------
    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= 0.95

    # ---------------------------------
    # Resolution dominance
    # ---------------------------------
    assert result["resolution"]["winner"] == "NodeNotReadyEvicted"
    assert "Evicted" in result["resolution"]["suppressed"]

    # ---------------------------------
    # Causal chain validation
    # ---------------------------------
    causes = result["causes"]

    assert causes[0]["code"] == "NODE_NOT_READY"
    assert causes[0]["blocking"] is True

    assert causes[1]["code"] == "POD_EVICTED"

    # ---------------------------------
    # Evidence validation
    # ---------------------------------
    for ev in expected.get("evidence", []):
        assert ev in result["evidence"]

    # ---------------------------------
    # Object evidence validation
    # ---------------------------------
    if "object_evidence" in expected:
        assert "object_evidence" in result
        for obj, items in expected["object_evidence"].items():
            assert obj in result["object_evidence"]
            for item in items:
                assert item in result["object_evidence"][obj]
