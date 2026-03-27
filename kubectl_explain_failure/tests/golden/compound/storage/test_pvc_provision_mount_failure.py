import json
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.rules.base.storage.volume_attach_failed import (
    VolumeAttachFailedRule,
)
from kubectl_explain_failure.rules.compound.storage.pvc_provision_mount_failure import (
    PVCProvisionThenMountFailureRule,
)
from kubectl_explain_failure.timeline import build_timeline

BASE_DIR = os.path.dirname(__file__)
FIXTURE_DIR = os.path.join(BASE_DIR, "pvc_provision_mount_failure")


def load_json(name: str):
    with open(os.path.join(FIXTURE_DIR, name)) as f:
        return json.load(f)


def test_pvc_provision_mount_failure_golden():
    data = load_json("input.json")
    expected = load_json("expected.json")

    pod = data["pod"]
    events = data.get("events", [])
    objects = data.get("objects", {})

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

    context["objects"] = objects
    context["serviceaccount"] = {"metadata": {"name": "default"}}
    context["secret"] = {"metadata": {"name": "registry-creds"}}

    if events:
        context["timeline"] = build_timeline(events, relative_to="last_event")

    context = normalize_context(context)

    result = explain_failure(
        pod,
        events,
        context=context,
        rules=[
            PVCProvisionThenMountFailureRule(),
            VolumeAttachFailedRule(),
        ],
    )

    assert result["root_cause"] == expected["root_cause"]
    assert result["blocking"] is True
    assert result["confidence"] >= expected["confidence"]

    assert result["resolution"]["winner"] == "PVCProvisionThenMountFailure"
    assert "VolumeAttachFailed" in result["resolution"]["suppressed"]

    for ev in expected["evidence"]:
        assert ev in result["evidence"]

    for exp_cause, res_cause in zip(expected["causes"], result["causes"], strict=False):
        assert exp_cause["code"] == res_cause["code"]
        assert exp_cause["message"] == res_cause["message"]
        assert exp_cause["role"] == res_cause["role"]
        assert exp_cause.get("blocking", False) == res_cause.get("blocking", False)
        assert exp_cause.get("blocking", True) == res_cause.get("blocking", True)

    for obj_key, items in expected["object_evidence"].items():
        assert obj_key in result["object_evidence"]
        for item in items:
            assert item in result["object_evidence"][obj_key]

    for lc in expected.get("likely_causes", []):
        assert lc in result.get("likely_causes", [])

    for sc in expected.get("suggested_checks", []):
        assert sc in result.get("suggested_checks", [])
