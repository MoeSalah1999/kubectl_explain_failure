from __future__ import annotations

import copy
import sys

from kubectl_explain_failure import cli


class _DummyRule:
    name = "Dummy"
    category = "Generic"
    priority = 1

    def matches(self, pod, events, context):
        return False

    def explain(self, pod, events, context):
        return {"root_cause": "x", "confidence": 0.1}


def test_cli_live_output_includes_provenance_metadata(monkeypatch):
    captured = {}

    pod = {
        "metadata": {"name": "mypod", "namespace": "default"},
        "status": {"phase": "Pending"},
    }
    events = [{"reason": "FailedScheduling", "lastTimestamp": "2024-01-01T00:00:00Z"}]
    context = {
        "objects": {
            "pvc": {"p1": {"metadata": {"name": "p1"}}},
            "node": {"n1": {"metadata": {"name": "n1"}}},
        }
    }
    warnings = ["kubectl get secret s1 failed: forbidden"]
    live_metadata = {
        "missing_kinds": ["secret"],
        "missing_kinds_by_reason": {"rbac_forbidden": ["secret"]},
        "missing_due_to_rbac": [
            {"kind": "secret", "name": "s1", "reason": "rbac_forbidden"}
        ],
        "completeness": {"missing_total": 1, "rbac_missing_total": 1},
    }

    def fake_fetch_live_snapshot(**kwargs):
        return (
            copy.deepcopy(pod),
            copy.deepcopy(events),
            copy.deepcopy(context),
            copy.deepcopy(warnings),
            copy.deepcopy(live_metadata),
        )

    def fake_explain_failure(*args, **kwargs):
        return {
            "root_cause": "Scheduler could not place Pod on any node",
            "confidence": 1.0,
            "evidence": [],
            "likely_causes": [],
            "suggested_checks": [],
            "blocking": True,
        }

    def fake_output_result(result, fmt):
        captured["result"] = result
        captured["format"] = fmt

    monkeypatch.setattr(cli, "fetch_live_snapshot", fake_fetch_live_snapshot)
    monkeypatch.setattr(cli, "explain_failure", fake_explain_failure)
    monkeypatch.setattr(cli, "output_result", fake_output_result)
    monkeypatch.setattr(cli, "load_rules", lambda rule_folder: [_DummyRule()])
    monkeypatch.setattr(cli, "load_plugins", lambda plugin_folder: [])
    monkeypatch.setattr(cli.shutil, "which", lambda _: "kubectl")

    monkeypatch.setattr(
        sys,
        "argv",
        ["kubectl_explain_failure", "pod", "mypod", "--live", "--format", "json"],
    )

    cli.main()

    result = captured["result"]
    assert captured["format"] == "json"

    assert result["source"] == "live"
    assert "provenance" in result
    assert result["provenance"]["source"] == "live"
    assert result["provenance"]["fetched_object_counts"] == {"pvc": 1, "node": 1}
    assert result["provenance"]["missing_kinds"] == ["secret"]
    assert result["provenance"]["missing_kinds_by_reason"] == {
        "rbac_forbidden": ["secret"]
    }
    assert result["provenance"]["fetch_warning_count"] == 1
    assert result["provenance"]["fetch_warnings"] == warnings
