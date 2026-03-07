from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given, settings, strategies as st

from kubectl_explain_failure import live_adapter
from kubectl_explain_failure.tests.property.strategies import K8sSnapshot, snapshot_strategy


def _ts(minute: int) -> str:
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return (base + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")


@settings(max_examples=80)
@given(
    snapshot=snapshot_strategy(),
    minutes=st.lists(st.integers(min_value=0, max_value=500), min_size=1, max_size=30, unique=True),
    event_limit=st.integers(min_value=1, max_value=15),
)
def test_property_live_adapter_event_output_is_chronological_and_capped(
    snapshot: K8sSnapshot,
    minutes: list[int],
    event_limit: int,
):
    pod_obj = copy.deepcopy(snapshot.pod)
    pod_obj.setdefault("metadata", {})["name"] = "mypod"
    pod_obj["metadata"].setdefault("namespace", "default")

    events = [
        {
            "reason": "FailedScheduling",
            "message": f"m={m}",
            "lastTimestamp": _ts(m),
        }
        for m in reversed(minutes)
    ]

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return {"kind": "List", "items": copy.deepcopy(events)}
        raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

    with patch.object(live_adapter, "_kubectl_get_json", side_effect=fake_get):
        _, fetched_events, _, _, _ = live_adapter.fetch_live_snapshot(
            pod_name="mypod",
            namespace="default",
            timeout_seconds=5,
            event_limit=event_limit,
        )

    got_minutes = [
        int(e["message"].split("=")[1])
        for e in fetched_events
        if isinstance(e.get("message"), str) and "=" in e["message"]
    ]

    expected = sorted(minutes)[-event_limit:]
    assert got_minutes == expected
    assert len(fetched_events) == min(event_limit, len(minutes))


@settings(max_examples=80)
@given(snapshot=snapshot_strategy())
def test_property_live_adapter_metadata_totals_are_self_consistent_with_generated_snapshot(
    snapshot: K8sSnapshot,
):
    pod_obj = copy.deepcopy(snapshot.pod)
    pod_obj.setdefault("metadata", {})["name"] = "mypod"
    pod_obj["metadata"].setdefault("namespace", "default")

    baseline = snapshot.clone()

    pvc_objects = copy.deepcopy(snapshot.context.get("objects", {}).get("pvc", {}))

    table: dict[tuple[str, str | None], dict] = {
        ("pod", "mypod"): pod_obj,
        ("events", None): {"kind": "List", "items": copy.deepcopy(snapshot.events)},
    }

    for v in pod_obj.get("spec", {}).get("volumes", []):
        claim_name = v.get("persistentVolumeClaim", {}).get("claimName") if isinstance(v, dict) else None
        if not claim_name:
            continue

        pvc_obj = pvc_objects.get(
            claim_name,
            {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": claim_name},
                "status": {"phase": "Bound"},
            },
        )
        table[("pvc", claim_name)] = pvc_obj

        pv_name = pvc_obj.get("spec", {}).get("volumeName")
        if pv_name:
            table[("pv", pv_name)] = {"metadata": {"name": pv_name}}

    def fake_get(kind, name=None, **kwargs):
        key = (kind, name)
        if key in table:
            return copy.deepcopy(table[key])
        raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

    with patch.object(live_adapter, "_kubectl_get_json", side_effect=fake_get):
        _, _, _, _, metadata = live_adapter.fetch_live_snapshot(
            pod_name="mypod",
            namespace="default",
            timeout_seconds=5,
            event_limit=200,
        )

    fetched_counts = metadata.get("fetched_object_counts", {})
    assert metadata.get("fetched_object_total") == sum(fetched_counts.values())
    assert metadata.get("event_count") == len(snapshot.events)
    assert metadata.get("fetch_warning_count") == len(metadata.get("missing_resources", []))

    assert snapshot.pod == baseline.pod
    assert snapshot.events == baseline.events
    assert snapshot.context == baseline.context
