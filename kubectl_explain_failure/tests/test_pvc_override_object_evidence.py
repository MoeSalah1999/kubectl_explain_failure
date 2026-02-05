import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json, normalize_events

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    return load_json(os.path.join(FIXTURES_DIR, name))


def test_pvc_override_wins_and_evidence_is_object_based():
    """
    Regression: PVC override + object_evidence

    Ensures:
    1. PVC-based rule overrides FailedScheduling / taint-based rules.
    2. Evidence is derived from PVC object state, not events.
    3. Result is stable even when scheduling events are present.
    """

    pod = load_fixture("pending_pod.json")
    pvc = load_fixture("pvc_pending.json")

    # Scheduling noise that *should not* win
    events = normalize_events(load_fixture("failed_scheduling_events_taint.json"))

    result = explain_failure(
        pod,
        events,
        context={"pvc": pvc},
    )

    # --- Root cause must come from PVC, not scheduling ---
    assert "persistentvolumeclaim" in result["root_cause"].lower()
    assert "unbound" in result["root_cause"].lower()

    # --- Confidence should be high and not diluted by event noise ---
    assert result["confidence"] >= 0.9

    # --- Evidence must reference PVC object state ---
    assert any(
        "PVC" in ev or "PersistentVolumeClaim" in ev or "Pending" in ev
        for ev in result["evidence"]
    )

    # --- Ensure scheduling evidence did not override PVC ---
    assert not any(
        "FailedScheduling" in ev or "taint" in ev.lower() for ev in result["evidence"]
    )
