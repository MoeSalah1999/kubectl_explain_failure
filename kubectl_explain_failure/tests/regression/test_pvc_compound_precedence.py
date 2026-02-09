import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.timeline import build_timeline

FIXTURES = os.path.join(
    os.path.dirname(__file__),
    "..",
    "golden",
    "pvc_pending_crashloop",
)


def test_compound_pvc_rule_beats_simple_pvc_rules():
    """
    Regression test:

    If a PVC is Pending AND the event timeline shows FailedMount + BackOff,
    the compound rule (PVCPendingThenCrashLoopRule) MUST win over
    PVCNotBoundRule or PVCMountFailedRule.

    This test prevents accidental semantic regression in:
    - PVC dominance override
    - rule priority handling
    - timeline-aware compound rules
    """

    with open(os.path.join(FIXTURES, "input.json")) as f:
        data = json.load(f)

    pod = data["pod"]
    events = data["events"]

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

    context["pvcs"] = data["pvcs"]
    context["timeline"] = build_timeline(events)

    # Canonical PVC signals
    context["blocking_pvc"] = data["pvcs"][0]
    context["pvc"] = data["pvcs"][0]

    result = explain_failure(pod, events, context=context)

    # ----------------------------
    # HARD ASSERTIONS (LOCKED)
    # ----------------------------

    # 1. Compound rule root cause must win
    assert (
        result["root_cause"] == "PVC Pending caused mount failures and CrashLoopBackOff"
    )

    # 2. Evidence must reflect timeline causality
    assert "Repeated FailedMount / BackOff events observed" in result["evidence"]

    # 3. PVC object evidence must be preserved
    assert "pvc:mypvc, phase:Pending" in result["object_evidence"]

    # 4. Engine must record correct resolution winner
    assert result["resolution"]["winner"] == "PVCPendingThenCrashLoop"

    # 5. Simpler PVC rules must be suppressed
    suppressed = result["resolution"]["suppressed"]
    assert "PVCNotBound" in suppressed
    assert "PVCMountFailed" in suppressed
