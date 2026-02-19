import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.model import load_json, normalize_events

# ----------------------------
# Fixtures directory
# ----------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

# ----------------------------
# Basic Pod Failure Rules
# ----------------------------




def test_failed_scheduling_taint():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(
        load_json(os.path.join(FIXTURES_DIR, "failed_scheduling_events_taint.json"))
    )

    result = explain_failure(pod, events)
    assert any("taint" in cause.lower() for cause in result["likely_causes"])



def test_crash_loop_backoff():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events([{"reason": "BackOff"}])

    result = explain_failure(pod, events)
    assert "crashing" in result["root_cause"].lower()
    assert any("BackOff" in ev for ev in result["evidence"])


def test_oom_killed():
    pod = {
        "metadata": {"name": "oom-pod"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"lastState": {"terminated": {"reason": "OOMKilled"}}}
            ],
        },
    }
    events = []

    result = explain_failure(pod, events)
    assert "out-of-memory" in result["root_cause"].lower()


def test_failed_mount():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES_DIR, "pvc_pending.json"))
    events = [{"reason": "FailedMount"}]

    context = normalize_context({"pvc": pvc})
    result = explain_failure(pod, events, context=context)
    assert "volume" in result["root_cause"].lower()


# ----------------------------
# Contextual / Cross-object Rules
# ----------------------------


def test_pvc_not_bound():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES_DIR, "pvc_pending.json"))
    events = []

    result = explain_failure(pod, events, context=normalize_context({"pvc": pvc}))
    assert result["root_cause"].startswith("PersistentVolumeClaim not bound")
    assert any("PVC" in ev for ev in result["evidence"])


def test_node_disk_pressure():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    node = load_json(os.path.join(FIXTURES_DIR, "node_disk_pressure.json"))
    events = [{"reason": "NodeDiskPressure"}]

    result = explain_failure(pod, events, context=normalize_context({"node": node}))
    assert "disk pressure" in result["root_cause"].lower()
    assert any("Node" in ev for ev in result["evidence"])




# ----------------------------
# Placeholder for future high-signal rules
# ----------------------------


@pytest.mark.skip(reason="Add more high-signal rules here")
def test_placeholder_new_rule():
    pass
