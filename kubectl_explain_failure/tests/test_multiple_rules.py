import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json, normalize_events

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")

# ----------------------------
# Fixture helpers
# ----------------------------


def load_fixture(filename):
    return load_json(os.path.join(FIXTURES_DIR, filename))


def test_pending_pvc_and_failed_scheduling():
    pod = load_fixture("pending_pod.json")
    pvc = load_fixture("pvc_pending.json")
    events = normalize_events([{"reason": "FailedScheduling"}])

    result = explain_failure(pod, events, {"pvc": pvc})
    assert "persistentvolumeclaim" in result["root_cause"].lower()
    assert 0 < result["confidence"] <= 1.0
    # Evidence should include both rules firing
    assert (
        any("Pending" in e for e in result["evidence"]) or len(result["evidence"]) > 0
    )


def test_image_pull_and_crashloop():
    pod = load_fixture("pending_pod.json")
    events = normalize_events([{"reason": "ErrImagePull"}, {"reason": "BackOff"}])

    result = explain_failure(pod, events)
    assert (
        "image" in result["root_cause"].lower()
        or "crash" in result["root_cause"].lower()
    )
    assert 0 < result["confidence"] <= 1.0
    assert len(result["evidence"]) >= 2


def test_oom_and_failed_mount():
    pod = {
        "metadata": {"name": "oom-pod"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"lastState": {"terminated": {"reason": "OOMKilled"}}}
            ],
        },
    }
    events = normalize_events([{"reason": "FailedMount"}])

    result = explain_failure(pod, events)
    # Root cause comes from highest confidence, others merged
    assert (
        "out-of-memory" in result["root_cause"].lower()
        or "mount" in result["root_cause"].lower()
    )
    assert len(result["evidence"]) >= 1
    assert 0 < result["confidence"] <= 1.0


def test_pending_with_no_events_low_confidence():
    pod = load_fixture("pending_pod.json")
    events = normalize_events([])

    result = explain_failure(pod, events)
    assert result["confidence"] <= 0.5  # confidence halved for no events
    assert "unknown" in result["root_cause"].lower()


def test_pvc_not_bound():
    pod = load_fixture("pending_pod.json")
    pvc = load_fixture("pvc_pending.json")
    events = load_fixture("events_pvc_not_bound.json")
    normalized_events = normalize_events(events["items"])

    result = explain_failure(pod, normalized_events, {"pvc": pvc})

    # Root cause should reference PVC not being bound
    assert "persistentvolumeclaim" in result["root_cause"].lower()
    # Confidence should be non-zero
    assert 0 < result["confidence"] <= 1.0
    # Evidence should include something about PVC or Pending status
    assert any(
        "PVC" in e or "volume" in e or "Pending" in e for e in result["evidence"]
    )


# ----------------------------
# Edge cases
# ----------------------------


def test_empty_pod_and_events():
    pod = {}
    events = []

    result = explain_failure(pod, events)
    assert result["root_cause"].lower() == "unknown"
    assert result["confidence"] == 0.0


def test_multiple_pods_independent():
    pod1 = load_fixture("pending_pod.json")
    pod2 = load_fixture("pending_pod.json")
    events1 = normalize_events([{"reason": "FailedScheduling"}])
    events2 = normalize_events([{"reason": "BackOff"}])

    res1 = explain_failure(pod1, events1)
    res2 = explain_failure(pod2, events2)

    assert res1 != res2
    assert res1["confidence"] > 0
    assert res2["confidence"] > 0
