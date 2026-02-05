import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json, normalize_events

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_pvc_blocks_failed_scheduling():
    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES, "pvc_pending.json"))

    events = normalize_events([
        {"reason": "FailedScheduling"}
    ])

    result = explain_failure(
        pod,
        events,
        context={"pvc": pvc},
    )

    # Root cause must be PVC
    assert "persistentvolumeclaim" in result["root_cause"].lower()

    # Resolution must exist
    assert "resolution" in result

    resolution = result["resolution"]

    # Scheduler rule must be suppressed
    assert "FailedScheduling" in resolution["suppressed"]

    # Winner must be PVC rule
    assert resolution["winner"] in {
        "PVCNotBound",
        "PVCMountFailed",
    }
