import os

import pytest

from kubectl_explain_failure.live_adapter import fetch_live_snapshot


RUN_FLAG = os.getenv("KUBECTL_EXPLAIN_FAILURE_RUN_LIVE_INTEGRATION") == "1"
POD_NAME = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_POD")
NAMESPACE = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_NAMESPACE", "default")
KUBECONFIG = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_KUBECONFIG")
KUBE_CONTEXT = os.getenv("KUBECTL_EXPLAIN_FAILURE_LIVE_CONTEXT")


pytestmark = pytest.mark.skipif(
    not RUN_FLAG,
    reason="Set KUBECTL_EXPLAIN_FAILURE_RUN_LIVE_INTEGRATION=1 to run live integration tests",
)


def test_live_adapter_fetch_smoke_from_real_cluster():
    if not POD_NAME:
        pytest.skip("Set KUBECTL_EXPLAIN_FAILURE_LIVE_POD to run integration fetch")

    pod, events, context, warnings, metadata = fetch_live_snapshot(
        pod_name=POD_NAME,
        namespace=NAMESPACE,
        kube_context=KUBE_CONTEXT,
        kubeconfig=KUBECONFIG,
        timeout_seconds=15,
        event_limit=100,
        event_chunk_size=100,
    )

    assert isinstance(pod, dict)
    assert pod.get("metadata", {}).get("name") == POD_NAME
    assert isinstance(events, list)
    assert isinstance(context, dict)
    assert "objects" in context
    assert isinstance(warnings, list)
    assert isinstance(metadata, dict)
    assert metadata.get("event_count") == len(events)
    assert metadata.get("fetch_warning_count") == len(warnings)
