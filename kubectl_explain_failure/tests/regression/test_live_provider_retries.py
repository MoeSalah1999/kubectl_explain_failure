from __future__ import annotations

import pytest

from kubectl_explain_failure import live_adapter
from kubectl_explain_failure.live_adapter import KubectlLiveDataProvider, LiveIntrospectionError


def test_kubectl_provider_retries_transient_errors(monkeypatch):
    calls = {"count": 0}

    def fake_kubectl_get_json(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise LiveIntrospectionError("unable to connect to the server")
        return {"kind": "Pod", "metadata": {"name": "mypod"}}

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_kubectl_get_json)

    provider = KubectlLiveDataProvider(max_retries=1, retry_backoff_seconds=0.001)
    obj = provider.get_json("pod", "mypod", namespace="default")

    assert obj["metadata"]["name"] == "mypod"
    assert calls["count"] == 2


def test_kubectl_provider_does_not_retry_non_retryable_errors(monkeypatch):
    calls = {"count": 0}

    def fake_kubectl_get_json(*args, **kwargs):
        calls["count"] += 1
        raise LiveIntrospectionError("forbidden: pods is forbidden")

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_kubectl_get_json)

    provider = KubectlLiveDataProvider(max_retries=3, retry_backoff_seconds=0.001)
    with pytest.raises(LiveIntrospectionError):
        provider.get_json("pod", "mypod", namespace="default")

    assert calls["count"] == 1
