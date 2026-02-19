import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "node_memorypressure")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_node_memorypressure_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    node = data.get("node")

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

    if node:
        context["node"] = node

    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["resolution"]["winner"] == "NodeMemoryPressure"
    assert result["blocking"] is True
    assert result["confidence"] >= 0.85

    assert result["causes"][0]["code"] == "NODE_MEMORY_PRESSURE"

    for ev in expected["evidence"]:
        assert ev in result["evidence"]
