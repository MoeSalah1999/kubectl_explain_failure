from __future__ import annotations

import sys

import pytest

from kubectl_explain_failure import cli
from kubectl_explain_failure.live_adapter import LiveIntrospectionError


def test_cli_live_mode_emits_structured_error_for_json(monkeypatch):
    captured: dict = {}

    def fake_fetch_live_snapshot(**kwargs):
        raise LiveIntrospectionError("kubectl get pod mypod failed: forbidden")

    def fake_output_result(result, fmt):
        captured["result"] = result
        captured["format"] = fmt

    monkeypatch.setattr(cli, "fetch_live_snapshot", fake_fetch_live_snapshot)
    monkeypatch.setattr(cli, "output_result", fake_output_result)
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")

    monkeypatch.setattr(
        sys,
        "argv",
        ["kubectl_explain_failure", "pod", "mypod", "--live", "--format", "json"],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
    assert captured["format"] == "json"
    assert captured["result"]["source"] == "live"
    assert captured["result"]["error"].startswith("kubectl get pod mypod failed")


def test_cli_live_mode_rejects_out_of_range_event_limit(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kubectl_explain_failure",
            "pod",
            "mypod",
            "--live",
            "--event-limit",
            "999999",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
