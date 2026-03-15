import copy
from unittest.mock import patch

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given
from hypothesis import strategies as st

from kubectl_explain_failure import live_adapter


@st.composite
def _pod_with_single_pvc(draw):
    pvc_name = draw(
        st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122),
            min_size=1,
            max_size=8,
        )
    )
    pvc_phase = draw(st.sampled_from(["Bound", "Pending", "Lost"]))

    pod = {
        "metadata": {"name": "p", "namespace": "default"},
        "spec": {
            "volumes": [
                {
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": pvc_name},
                }
            ]
        },
        "status": {"phase": "Pending"},
    }

    pvc = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": pvc_name},
        "status": {"phase": pvc_phase},
    }

    return pod, pvc


@given(payload=_pod_with_single_pvc())
def test_property_live_adapter_normalizes_pvc_blocking_flags(payload):
    pod_obj, pvc_obj = payload

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return {"kind": "List", "items": []}
        if (kind, name) == ("pvc", pvc_obj["metadata"]["name"]):
            return copy.deepcopy(pvc_obj)
        raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

    with patch.object(live_adapter, "_kubectl_get_json", side_effect=fake_get):
        _, _, context, warnings, _ = live_adapter.fetch_live_snapshot(
            pod_name="mypod",
            namespace="default",
            timeout_seconds=5,
        )

    name = pvc_obj["metadata"]["name"]
    phase = pvc_obj["status"]["phase"]

    assert "pvc" in context.get("objects", {})
    assert name in context["objects"]["pvc"]

    if phase != "Bound":
        assert context.get("pvc_unbound") is True
        assert context.get("blocking_pvc", {}).get("metadata", {}).get("name") == name
        assert context.get("pvc", {}).get("metadata", {}).get("name") == name
    else:
        assert context.get("pvc_unbound") is not True

    assert isinstance(warnings, list)


@given(
    reasons=st.lists(
        st.sampled_from(["forbidden", "not found", "other"]),
        min_size=3,
        max_size=3,
    )
)
def test_property_live_adapter_metadata_counts_are_consistent(reasons):
    pod_obj = {
        "metadata": {
            "name": "mypod",
            "namespace": "default",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-a"}],
        },
        "spec": {
            "nodeName": "node-a",
            "serviceAccountName": "sa-a",
            "volumes": [
                {"name": "data", "persistentVolumeClaim": {"claimName": "pvc-a"}}
            ],
        },
        "status": {"phase": "Pending"},
    }

    error_for_kind = {
        "pvc": reasons[0],
        "node": reasons[1],
        "serviceaccount": reasons[2],
    }

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return {"kind": "List", "items": []}

        token = error_for_kind.get(kind)
        if token == "forbidden":
            raise live_adapter.LiveIntrospectionError(f"forbidden: {kind}/{name}")
        if token == "not found":
            raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

        raise live_adapter.LiveIntrospectionError(f"boom: {kind}/{name}")

    with patch.object(live_adapter, "_kubectl_get_json", side_effect=fake_get):
        _, _, _, warnings, metadata = live_adapter.fetch_live_snapshot(
            pod_name="mypod",
            namespace="default",
            timeout_seconds=5,
        )

    missing = metadata.get("missing_resources", [])
    assert metadata.get("completeness", {}).get("missing_total") == len(missing)
    assert metadata.get("fetch_warning_count") == len(warnings)

    missing_kinds = set(metadata.get("missing_kinds", []))
    expected_kinds = {m.get("kind") for m in missing if m.get("kind")}
    assert missing_kinds == expected_kinds

    by_reason = metadata.get("missing_kinds_by_reason", {})
    for reason, kinds in by_reason.items():
        observed = {m.get("kind") for m in missing if m.get("reason") == reason}
        assert set(kinds) == observed

    rbac_missing = [m for m in missing if m.get("reason") == "rbac_forbidden"]
    assert metadata.get("completeness", {}).get("rbac_missing_total") == len(
        rbac_missing
    )
