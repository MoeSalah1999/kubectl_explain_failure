from __future__ import annotations

import sys

import pytest

from kubectl_explain_failure import cli


def test_cli_live_mode_requires_kubectl_in_path(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)

    monkeypatch.setattr(
        sys,
        "argv",
        ["kubectl_explain_failure", "pod", "mypod", "--live"],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_cli_live_mode_rejects_missing_kubeconfig_path(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")
    monkeypatch.setattr(cli.os.path, "isfile", lambda _: False)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "kubectl_explain_failure",
            "pod",
            "mypod",
            "--live",
            "--kubeconfig",
            "C:/does/not/exist/kubeconfig",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2
