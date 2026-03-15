from __future__ import annotations

import sys

import pytest

from kubectl_explain_failure import cli


class _DummyRule:
    name = "Dummy"
    category = "Generic"
    priority = 1

    def matches(self, pod, events, context):
        return False

    def explain(self, pod, events, context):
        return {"root_cause": "x", "confidence": 0.1}


def test_cli_live_passes_retry_parameters_to_live_adapter(monkeypatch):
    captured: dict = {}

    def fake_fetch_live_snapshot(**kwargs):
        captured.update(kwargs)
        return (
            {"metadata": {"name": "mypod"}, "status": {"phase": "Pending"}},
            [],
            {"objects": {}},
            [],
            {
                "missing_due_to_rbac": [],
                "completeness": {"missing_total": 0, "rbac_missing_total": 0},
            },
        )

    def fake_explain_failure(*args, **kwargs):
        return {
            "root_cause": "Scheduler could not place Pod on any node",
            "confidence": 0.9,
            "evidence": [],
            "likely_causes": [],
            "suggested_checks": [],
            "blocking": True,
        }

    monkeypatch.setattr(cli, "fetch_live_snapshot", fake_fetch_live_snapshot)
    monkeypatch.setattr(cli, "explain_failure", fake_explain_failure)
    monkeypatch.setattr(cli, "output_result", lambda *_: None)
    monkeypatch.setattr(cli, "load_rules", lambda *_, **__: [_DummyRule()])
    monkeypatch.setattr(cli, "load_plugins", lambda *_, **__: [])
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kubectl_explain_failure",
            "pod",
            "mypod",
            "--live",
            "--retries",
            "3",
            "--retry-backoff",
            "1.5",
        ],
    )

    cli.main()

    assert captured["retry_count"] == 3
    assert captured["retry_backoff_seconds"] == 1.5


def test_cli_live_mode_rejects_out_of_range_retry_backoff(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kubectl_explain_failure",
            "pod",
            "mypod",
            "--live",
            "--retry-backoff",
            "99",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
