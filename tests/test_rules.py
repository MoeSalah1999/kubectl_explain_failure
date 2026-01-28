import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from explain_failure import explain_failure, load_json, normalize_events

# ----------------------------
# Basic Pod Failure Rules
# ----------------------------

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

def test_failed_scheduling():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(load_json(os.path.join(FIXTURES_DIR, "failed_scheduling_events.json")))

    result = explain_failure(pod, events)
    assert result["root_cause"] == "Pod could not be scheduled"
    assert "FailedScheduling" in "".join(result["evidence"])

def test_failed_scheduling_taint():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(load_json(os.path.join(FIXTURES_DIR, "failed_scheduling_events_taint.json")))

    result = explain_failure(pod, events)
    assert "taints" in " ".join(result["likely_causes"]).lower()

def test_image_pull_error():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(
        load_json(os.path.join(FIXTURES_DIR, "events_image_pull_secret_missing.json"))
    )

    result = explain_failure(pod, events)
    # Check that the rule triggers
    assert "image pull secret" in result["root_cause"].lower()
    # Match the exact likely_causes in the rule
    assert "imagePullSecrets not defined" in result["likely_causes"]
    assert "Secret exists in wrong namespace" in result["likely_causes"]

def test_crash_loop_backoff():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = [{"reason": "BackOff"}]

    result = explain_failure(pod, events)
    assert "crashing" in result["root_cause"].lower()
    assert "BackOff" in "".join(result["evidence"])

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
    events = [{"reason": "FailedMount"}]

    result = explain_failure(pod, events)
    assert "volume" in result["root_cause"].lower()
    assert "FailedMount" in "".join(result["evidence"])

# ----------------------------
# Cross-object / Contextual Rules
# ----------------------------

def test_pvc_not_bound():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES_DIR, "pvc_pending.json"))
    events = []

    result = explain_failure(pod, events, context={"pvc": pvc})
    assert result["root_cause"].startswith("Pod is blocked by unbound")
    assert "PVC" in " ".join(result["evidence"])

def test_node_disk_pressure():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    node = load_json(os.path.join(FIXTURES_DIR, "node_disk_pressure.json"))
    events = []

    result = explain_failure(pod, events, context={"node": node})
    assert "disk pressure" in result["root_cause"].lower()
    assert "Node" in " ".join(result["evidence"])

# ----------------------------
# New high-signal rules
# ----------------------------

def test_missing_configmap():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(load_json(os.path.join(FIXTURES_DIR, "events_configmap_missing.json")))

    result = explain_failure(pod, events)
    assert "ConfigMap" in result["root_cause"]

def test_image_pull_secret_missing():
    pod = load_json(os.path.join(FIXTURES_DIR, "pending_pod.json"))
    events = normalize_events(load_json(os.path.join(FIXTURES_DIR, "events_image_pull_secret_missing.json")))

    result = explain_failure(pod, events)
    assert "image" in result["root_cause"].lower()
    assert any("secret" in cause.lower() for cause in result["likely_causes"])

# Placeholder for other new rules I might add
@pytest.mark.skip(reason="Add more high-signal rules here")
def test_placeholder_new_rule():
    pass
