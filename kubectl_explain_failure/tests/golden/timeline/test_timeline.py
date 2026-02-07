import json
import os

from kubectl_explain_failure.timeline import build_timeline

BASE = os.path.dirname(__file__)
CASES = os.path.join(BASE, "cases")
EXPECTED = os.path.join(BASE, "expected")


def load(name):
    with open(os.path.join(CASES, name)) as f:
        case = json.load(f)
    with open(os.path.join(EXPECTED, name)) as f:
        expected = json.load(f)
    return case, expected


def test_timeline_golden_cases():
    for name in os.listdir(CASES):
        case, expected = load(name)
        timeline = build_timeline(case["events"])

        assert timeline.has(
            kind=expected["dominant_kind"],
            phase=expected["dominant_phase"],
        )

        kinds = {e.kind for e in timeline.normalized}
        phases = {e.phase for e in timeline.normalized}

        assert kinds == set(expected["kinds_present"])
        assert phases == set(expected["phases_present"])
