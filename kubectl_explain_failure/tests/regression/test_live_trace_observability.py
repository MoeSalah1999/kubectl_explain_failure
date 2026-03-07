from __future__ import annotations

import copy
import sys

from kubectl_explain_failure import cli, live_adapter


def test_live_adapter_includes_trace_id_in_metadata(monkeypatch):
    pod_obj = {
        "metadata": {"name": "mypod", "namespace": "default"},
        "spec": {},
        "status": {"phase": "Pending"},
    }

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return {"kind": "List", "items": []}
        raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    _, _, _, _, metadata = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        trace_id="trace-123",
    )

    assert metadata.get("trace_id") == "trace-123"


def test_cli_live_provenance_includes_trace_id(monkeypatch):
    captured = {}

    def fake_fetch_live_snapshot(**kwargs):
        return (
            {"metadata": {"name": "mypod"}, "status": {"phase": "Pending"}},
            [],
            {"objects": {}},
            [],
            {
                "trace_id": kwargs.get("trace_id"),
                "missing_due_to_rbac": [],
                "completeness": {"missing_total": 0, "rbac_missing_total": 0},
                "missing_kinds": [],
                "missing_kinds_by_reason": {},
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

    def fake_output_result(result, fmt):
        captured["result"] = result

    monkeypatch.setattr(cli, "fetch_live_snapshot", fake_fetch_live_snapshot)
    monkeypatch.setattr(cli, "explain_failure", fake_explain_failure)
    monkeypatch.setattr(cli, "output_result", fake_output_result)
    monkeypatch.setattr(cli, "load_rules", lambda *_, **__: [])
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
            "--trace-id",
            "trace-abc",
            "--format",
            "json",
        ],
    )

    cli.main()

    assert captured["result"]["provenance"].get("trace_id") == "trace-abc"
