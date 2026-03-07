from __future__ import annotations

import sys

from kubectl_explain_failure import plugin


def test_plugin_translates_args_to_live_cli(monkeypatch):
    captured: dict = {}

    def fake_cli_main():
        captured["argv"] = list(sys.argv)

    monkeypatch.setattr(plugin, "cli_main", fake_cli_main)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kubectl-explain-failure",
            "mypod",
            "-n",
            "ns1",
            "--context",
            "ctx-a",
            "--retries",
            "2",
            "--retry-backoff",
            "0.5",
            "--format",
            "json",
        ],
    )

    plugin.main()

    argv = captured["argv"]
    assert argv[0] == "kubectl-explain-failure"
    assert argv[1:4] == ["pod", "mypod", "--live"]
    assert "--namespace" in argv and "ns1" in argv
    assert "--context" in argv and "ctx-a" in argv
    assert "--retries" in argv and "2" in argv
    assert "--retry-backoff" in argv and "0.5" in argv
    assert "--format" in argv and "json" in argv
