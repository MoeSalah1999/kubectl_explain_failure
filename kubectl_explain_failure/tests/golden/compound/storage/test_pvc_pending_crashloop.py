import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.timeline import build_timeline

FIXTURES = os.path.join(os.path.dirname(__file__), "pvc_pending_crashloop")


def test_pvc_pending_then_crashloop_golden():
    with open(os.path.join(FIXTURES, "input.json")) as f:
        data = json.load(f)
    pod = data["pod"]
    events = data.get("events", [])
    # Create a dummy Args object with all expected attributes
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
    context["timeline"] = build_timeline(events, relative_to="last_event")
    context["pvcs"] = data.get("pvcs", [])
    if context["pvcs"]:
        context["blocking_pvc"] = context["pvcs"][0]
        context["pvc"] = context["pvcs"][0]
    result = explain_failure(pod, events, context=context)
    with open(os.path.join(FIXTURES, "expected.json")) as f:
        expected = json.load(f)

    # Root cause validation
    assert result["root_cause"] == expected["root_cause"]

    # Confidence validation
    assert result["confidence"] >= expected["confidence"]

    # Causes
    for exp_cause, res_cause in zip(expected["causes"], result["causes"]):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)
