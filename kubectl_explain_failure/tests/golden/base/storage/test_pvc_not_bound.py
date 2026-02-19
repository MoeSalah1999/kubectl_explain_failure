import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure

FIXTURES = os.path.join(os.path.dirname(__file__), "pvc_not_bound")


def test_pvc_pending_golden():
    with open(os.path.join(FIXTURES, "input.json")) as f:
        data = json.load(f)

    pod = data["pod"]
    events = data.get("events", [])

    ctx_args = type("Args", (), {})()
    ctx_args.pvc = None
    ctx_args.pvcs = None
    ctx_args.pv = None
    ctx_args.node = None
    ctx_args.storageclass = None
    ctx_args.serviceaccount = None
    ctx_args.secret = None
    ctx_args.replicaset = None
    ctx_args.deployment = None
    ctx_args.statefulsets = None
    ctx_args.daemonsets = None

    context = build_context(ctx_args)
    context["pvcs"] = data.get("pvcs", [])
    if context["pvcs"]:
        context["pvc_unbound"] = True
        context["blocking_pvc"] = context["pvcs"][0]
        context["pvc"] = context["pvcs"][0]

    result = explain_failure(pod, events, context)

    with open(os.path.join(FIXTURES, "expected.json")) as f:
        expected = json.load(f)

    for key in expected:
        assert result.get(key) == expected[key], f"Mismatch on {key}"
