from __future__ import annotations

from unittest.mock import patch

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import given, settings
from hypothesis import strategies as st

from kubectl_explain_failure import live_adapter
from kubectl_explain_failure.live_adapter import (
    KubectlLiveDataProvider,
    LiveIntrospectionError,
)


@settings(max_examples=80)
@given(
    retry_count=st.integers(min_value=0, max_value=5),
    fail_count=st.integers(min_value=0, max_value=7),
)
def test_property_provider_retry_limit_contract(retry_count: int, fail_count: int):
    calls = {"count": 0}

    def fake_kubectl_get_json(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] <= fail_count:
            raise LiveIntrospectionError("unable to connect to the server")
        return {"kind": "Pod", "metadata": {"name": "mypod"}}

    with patch.object(
        live_adapter, "_kubectl_get_json", side_effect=fake_kubectl_get_json
    ):
        with patch.object(live_adapter.time, "sleep", side_effect=lambda *_: None):
            provider = KubectlLiveDataProvider(
                max_retries=retry_count,
                retry_backoff_seconds=0.001,
            )

            if fail_count <= retry_count:
                out = provider.get_json("pod", "mypod", namespace="default")
                assert out["metadata"]["name"] == "mypod"
                assert calls["count"] == fail_count + 1
            else:
                with pytest.raises(LiveIntrospectionError):
                    provider.get_json("pod", "mypod", namespace="default")
                assert calls["count"] == retry_count + 1


@settings(max_examples=60)
@given(
    retry_count=st.integers(min_value=0, max_value=5),
    message=st.sampled_from(
        [
            "forbidden: pods is forbidden",
            "not found: pod/mypod",
            "invalid json",
            "admission denied",
        ]
    ),
)
def test_property_provider_non_retryable_errors_do_not_retry(
    retry_count: int, message: str
):
    calls = {"count": 0}

    def fake_kubectl_get_json(*args, **kwargs):
        calls["count"] += 1
        raise LiveIntrospectionError(message)

    with patch.object(
        live_adapter, "_kubectl_get_json", side_effect=fake_kubectl_get_json
    ):
        with patch.object(live_adapter.time, "sleep", side_effect=lambda *_: None):
            provider = KubectlLiveDataProvider(
                max_retries=retry_count,
                retry_backoff_seconds=0.001,
            )

            with pytest.raises(LiveIntrospectionError):
                provider.get_json("pod", "mypod", namespace="default")

    assert calls["count"] == 1
