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
