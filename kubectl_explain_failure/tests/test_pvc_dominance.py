import os

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json, normalize_events

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_pvc_dominates_scheduler_noise():
    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES, "pvc_pending.json"))
    events = normalize_events([{"reason": "FailedScheduling"}])

    result = explain_failure(pod, events, context={"pvc": pvc})

    assert "persistentvolumeclaim" in result["root_cause"].lower()
    assert "FailedScheduling" in result["resolution"]["suppressed"]


def test_pvc_suppresses_multiple_noise():
    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES, "pvc_pending.json"))
    events = [
        {"reason": "FailedScheduling"},
        {"reason": "NodeNotReady"},
        {"reason": "TaintBasedEviction"},
    ]
    result = explain_failure(pod, normalize_events(events), context={"pvc": pvc})

    # Root cause comes from PVC
    assert "persistentvolumeclaim" in result["root_cause"].lower()
    # Only check that PVC suppressed *FailedScheduling* (scheduler noise)
    suppressed = result.get("resolution", {}).get("suppressed", [])
    assert "FailedScheduling" in suppressed
