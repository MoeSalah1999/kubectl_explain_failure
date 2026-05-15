import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "recovered_but_dependent_failure_remains")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_recovered_but_dependent_failure_remains_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])

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

    context["pvc"] = data["pvc"]
    context["timeline"] = build_timeline(events, relative_to="last_event")
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= expected["confidence"]

    assert result["resolution"]["winner"] == expected["resolution"]["winner"]
    assert (
        result["resolution"]["explained_by"] == expected["resolution"]["explained_by"]
    )

    recovered = result["recovered_but_dependent_failure_remains"]
    assert (
        recovered["winner"]
        == expected["recovered_but_dependent_failure_remains"]["winner"]
    )
    assert (
        recovered["recovered_domain"]
        == expected["recovered_but_dependent_failure_remains"]["recovered_domain"]
    )
    assert (
        recovered["dependent_failure_domain"]
        == expected["recovered_but_dependent_failure_remains"][
            "dependent_failure_domain"
        ]
    )
    assert (
        recovered["recovery"]["reason"]
        == expected["recovered_but_dependent_failure_remains"]["recovery"]["reason"]
    )
    assert (
        recovered["remaining_failure"]["reason"]
        == expected["recovered_but_dependent_failure_remains"]["remaining_failure"][
            "reason"
        ]
    )

    for reason in expected["recovered_but_dependent_failure_remains"][
        "recent_event_reasons"
    ]:
        assert reason in recovered["recent_event_reasons"]

    for exp_cause in expected["causes"]:
        assert exp_cause in result["causes"]

    for ev in expected["evidence"]:
        assert ev in result["evidence"]
