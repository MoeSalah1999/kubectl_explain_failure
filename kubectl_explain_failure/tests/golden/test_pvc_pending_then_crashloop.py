import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.timeline import build_timeline

FIXTURES = os.path.join(os.path.dirname(__file__), "pvc_pending_then_crashloop")


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
    context["timeline"] = build_timeline(events)
    context["pvcs"] = data.get("pvcs", [])
    if context["pvcs"]:
        context["blocking_pvc"] = context["pvcs"][0]
        context["pvc"] = context["pvcs"][0]
    result = explain_failure(pod, events, context=context)
    with open(os.path.join(FIXTURES, "expected.json")) as f:
        expected = json.load(f)
    for key in expected:
        assert result.get(key) == expected[key], f"Mismatch on {key}"
