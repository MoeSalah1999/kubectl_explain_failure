import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

FIXTURES = os.path.join(os.path.dirname(__file__), "pvc_bound_node_pressure")


def load_json(name: str):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def test_pvc_bound_then_node_pressure_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["objects"]["pod"]  
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

    context["objects"]["pod"] = {"mypod": pod}
    context["objects"]["pvc"] = data["objects"].get("pvc", {})
    context["objects"]["node"] = data["objects"].get("node", {})
    context["timeline"] = build_timeline(events, relative_to="last_event")

    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    # Root cause
    assert result["root_cause"] == expected["root_cause"]

    # Confidence
    assert result["confidence"] >= expected["confidence"]

    # Causal chain
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)
