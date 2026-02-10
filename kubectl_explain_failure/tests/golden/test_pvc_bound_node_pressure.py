import os
import json

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

FIXTURES = os.path.join(
    os.path.dirname(__file__),
    "pvc_bound_node_pressure",
)


def test_pvc_bound_then_node_pressure_golden():
    with open(os.path.join(FIXTURES, "input.json")) as f:
        data = json.load(f)

    pod = data
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

    # PVCs supplied via fixture (even if bound)
    context["pvcs"] = data.get("pvcs", [])

    # Timeline is always explicit
    context["timeline"] = build_timeline(events)

    # Normalize context (critical for PVC + Node interactions)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    with open(os.path.join(FIXTURES, "expected.json")) as f:
        expected = json.load(f)

    for key in expected:
        assert result.get(key) == expected[key], f"Mismatch on {key}"
