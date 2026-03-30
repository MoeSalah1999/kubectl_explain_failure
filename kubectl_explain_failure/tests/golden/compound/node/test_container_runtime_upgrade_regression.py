import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "container_runtime_upgrade_regression")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def test_container_runtime_upgrade_regression_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    node = data.get("node")

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

    if node:
        context["node"] = node

    context["timeline"] = build_timeline(events, relative_to="last_event")
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= expected["confidence"]

    assert result["resolution"]["winner"] == "ContainerRuntimeUpgradeRegression"
    for suppressed in expected["resolution"]["suppressed"]:
        assert suppressed in result["resolution"]["suppressed"]

    for exp_cause, res_cause in zip(expected["causes"], result["causes"], strict=False):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)

    for ev in expected.get("evidence", []):
        assert ev in result["evidence"]

    for obj, items in expected.get("object_evidence", {}).items():
        assert obj in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj]

    for lc in expected.get("likely_causes", []):
        assert lc in result["likely_causes"]

    for check in expected.get("suggested_checks", []):
        assert check in result["suggested_checks"]
