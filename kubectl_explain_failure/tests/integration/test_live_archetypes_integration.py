import os

import pytest

from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.live_adapter import fetch_live_snapshot

RUN_FLAG = os.getenv("KUBECTL_EXPLAIN_FAILURE_RUN_LIVE_INTEGRATION") == "1"
NAMESPACE = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_NAMESPACE", "default")
KUBECONFIG = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_KUBECONFIG")
KUBE_CONTEXT = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_CONTEXT")

POD_PVC_PENDING = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_POD_PVC_PENDING")
POD_SCHEDULING = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_POD_SCHEDULING")
POD_CRASHLOOP = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_POD_CRASHLOOP")
POD_IMAGEPULL = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_POD_IMAGEPULL")


pytestmark = pytest.mark.skipif(
    not RUN_FLAG,
    reason="Set KUBECTL_EXPLAIN_FAILURE_RUN_LIVE_INTEGRATION=1 to run live integration tests",
)


def _explain_live_pod(pod_name: str) -> tuple[dict, dict]:
    pod, events, context, warnings, metadata = fetch_live_snapshot(
        pod_name=pod_name,
        namespace=NAMESPACE,
        kube_context=KUBE_CONTEXT,
        kubeconfig=KUBECONFIG,
        timeout_seconds=20,
        event_limit=200,
        event_chunk_size=200,
        retry_count=2,
        retry_backoff_seconds=0.5,
    )

    result = explain_failure(pod, events, context)

    assert isinstance(result, dict)
    assert isinstance(result.get("root_cause"), str)
    assert 0.0 <= float(result.get("confidence", 0.0)) <= 1.0
    assert isinstance(result.get("blocking"), bool)

    assert metadata.get("event_count") == len(events)
    assert metadata.get("fetch_warning_count") == len(warnings)

    return result, metadata


def _cause_codes(result: dict) -> set[str]:
    return {
        c.get("code")
        for c in result.get("causes", [])
        if isinstance(c, dict) and isinstance(c.get("code"), str)
    }


def test_live_archetype_pvc_pending_maps_to_volume_blocker():
    if not POD_PVC_PENDING:
        pytest.skip("Set KUBECTL_EXPLAIN_FAILURE_LIVE_POD_PVC_PENDING")

    result, _ = _explain_live_pod(POD_PVC_PENDING)
    root = result.get("root_cause", "").lower()
    codes = _cause_codes(result)

    assert result.get("blocking") is True
    assert (
        "persistentvolumeclaim" in root
        or "pvc" in root
        or any(code.startswith("PVC_") for code in codes)
    )


def test_live_archetype_scheduling_maps_to_scheduler_signal():
    if not POD_SCHEDULING:
        pytest.skip("Set KUBECTL_EXPLAIN_FAILURE_LIVE_POD_SCHEDULING")

    result, _ = _explain_live_pod(POD_SCHEDULING)
    root = result.get("root_cause", "").lower()
    codes = _cause_codes(result)
    winner = (result.get("resolution") or {}).get("winner", "")

    assert (
        "schedul" in root
        or "failedscheduling" in winner.lower()
        or "insufficient" in winner.lower()
        or "taint" in winner.lower()
        or "SCHEDULER_REJECTION" in codes
    )


def test_live_archetype_crashloop_maps_to_container_crash_signal():
    if not POD_CRASHLOOP:
        pytest.skip("Set KUBECTL_EXPLAIN_FAILURE_LIVE_POD_CRASHLOOP")

    result, _ = _explain_live_pod(POD_CRASHLOOP)
    root = result.get("root_cause", "").lower()
    codes = _cause_codes(result)

    assert "crashloop" in root or "backoff" in root or "CONTAINER_CRASHING" in codes


def test_live_archetype_imagepull_maps_to_image_pull_signal():
    if not POD_IMAGEPULL:
        pytest.skip("Set KUBECTL_EXPLAIN_FAILURE_LIVE_POD_IMAGEPULL")

    result, _ = _explain_live_pod(POD_IMAGEPULL)
    root = result.get("root_cause", "").lower()
    codes = _cause_codes(result)

    assert (
        "image" in root
        or "pull" in root
        or any(code.startswith("IMAGE_PULL") for code in codes)
    )
