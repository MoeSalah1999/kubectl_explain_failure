import copy

from kubectl_explain_failure import live_adapter


def test_fetch_live_snapshot_discovers_dependency_objects(monkeypatch):
    pod_obj = {
        "metadata": {
            "name": "mypod",
            "namespace": "default",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-a"}],
        },
        "spec": {
            "nodeName": "node-a",
            "serviceAccountName": "sa-a",
            "imagePullSecrets": [{"name": "pull-secret"}],
            "volumes": [
                {"name": "data", "persistentVolumeClaim": {"claimName": "pvc-a"}},
                {"name": "cfg", "secret": {"secretName": "app-secret"}},
            ],
            "containers": [
                {
                    "name": "app",
                    "env": [
                        {
                            "name": "PASSWORD",
                            "valueFrom": {
                                "secretKeyRef": {"name": "env-secret", "key": "pw"}
                            },
                        }
                    ],
                }
            ],
        },
        "status": {"phase": "Pending"},
    }

    pvc_obj = {
        "metadata": {"name": "pvc-a"},
        "spec": {"volumeName": "pv-a", "storageClassName": "sc-a"},
        "status": {"phase": "Pending"},
    }

    table = {
        ("pod", "mypod"): pod_obj,
        ("events", None): {"kind": "List", "items": [{"reason": "FailedScheduling"}]},
        ("pvc", "pvc-a"): pvc_obj,
        ("pv", "pv-a"): {"metadata": {"name": "pv-a"}},
        ("storageclass", "sc-a"): {"metadata": {"name": "sc-a"}},
        ("node", "node-a"): {
            "metadata": {"name": "node-a"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        },
        ("replicaset", "rs-a"): {
            "metadata": {
                "name": "rs-a",
                "ownerReferences": [{"kind": "Deployment", "name": "deploy-a"}],
            }
        },
        ("deployment", "deploy-a"): {"metadata": {"name": "deploy-a"}},
        ("serviceaccount", "sa-a"): {
            "metadata": {"name": "sa-a"},
            "secrets": [{"name": "sa-token"}],
            "imagePullSecrets": [{"name": "sa-pull-secret"}],
        },
        ("secret", "pull-secret"): {"metadata": {"name": "pull-secret"}},
        ("secret", "app-secret"): {"metadata": {"name": "app-secret"}},
        ("secret", "env-secret"): {"metadata": {"name": "env-secret"}},
        ("secret", "sa-token"): {"metadata": {"name": "sa-token"}},
        ("secret", "sa-pull-secret"): {"metadata": {"name": "sa-pull-secret"}},
    }

    def fake_get(kind, name=None, **kwargs):
        key = (kind, name)
        if key not in table:
            raise AssertionError(f"unexpected kubectl request: {key}")
        return copy.deepcopy(table[key])

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    pod, events, context, warnings, live_metadata = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
    )

    assert pod["metadata"]["name"] == "mypod"
    assert events and events[0]["reason"] == "FailedScheduling"
    assert warnings == []
    assert live_metadata["completeness"]["missing_total"] == 0

    objects = context["objects"]
    assert "pvc-a" in objects["pvc"]
    assert "pv-a" in objects["pv"]
    assert "sc-a" in objects["storageclass"]
    assert "node-a" in objects["node"]
    assert "rs-a" in objects["replicaset"]
    assert "deploy-a" in objects["deployment"]
    assert "sa-a" in objects["serviceaccount"]
    assert "pull-secret" in objects["secret"]
    assert "app-secret" in objects["secret"]
    assert "env-secret" in objects["secret"]
    assert "sa-token" in objects["secret"]
    assert "sa-pull-secret" in objects["secret"]

    assert context["owner"]["metadata"]["name"] == "deploy-a"
    assert context.get("pvc_unbound") is True
    assert context.get("blocking_pvc", {}).get("metadata", {}).get("name") == "pvc-a"
    assert context.get("pvc", {}).get("metadata", {}).get("name") == "pvc-a"
    assert context.get("node_conditions", {}).get("Ready", {}).get("status") == "True"


def test_fetch_live_snapshot_keeps_partial_context_on_fetch_failures(monkeypatch):
    pod_obj = {
        "metadata": {
            "name": "mypod",
            "namespace": "default",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-a"}],
        },
        "spec": {
            "nodeName": "node-a",
            "volumes": [
                {"name": "data", "persistentVolumeClaim": {"claimName": "pvc-a"}}
            ],
        },
        "status": {"phase": "Pending"},
    }

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return {"kind": "List", "items": []}
        if (kind, name) == ("node", "node-a"):
            return {"metadata": {"name": "node-a"}}
        raise live_adapter.LiveIntrospectionError(f"forbidden: {kind}/{name}")

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    pod, events, context, warnings, live_metadata = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
    )

    assert pod["metadata"]["name"] == "mypod"
    assert events == []
    assert "node" in context["objects"]
    assert warnings
    assert live_metadata["completeness"]["missing_total"] >= 1


def test_fetch_live_snapshot_owner_chain_partial_failure_still_keeps_first_owner(
    monkeypatch,
):
    pod_obj = {
        "metadata": {
            "name": "mypod",
            "namespace": "default",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-a"}],
        },
        "spec": {},
        "status": {"phase": "Pending"},
    }

    table = {
        ("pod", "mypod"): pod_obj,
        ("events", None): {"kind": "List", "items": []},
        ("replicaset", "rs-a"): {
            "metadata": {
                "name": "rs-a",
                "ownerReferences": [{"kind": "Deployment", "name": "deploy-a"}],
            }
        },
    }

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) in table:
            return copy.deepcopy(table[(kind, name)])
        if (kind, name) == ("deployment", "deploy-a"):
            raise live_adapter.LiveIntrospectionError("forbidden: deployment/deploy-a")
        raise AssertionError(f"unexpected kubectl request: {(kind, name)}")

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    _, _, context, warnings, live_metadata = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
    )

    assert "replicaset" in context["objects"]
    assert "rs-a" in context["objects"]["replicaset"]
    assert "owner" in context
    assert context["owner"]["metadata"]["name"] == "rs-a"
    assert warnings
    assert any(
        m["reason"] == "rbac_forbidden" for m in live_metadata["missing_resources"]
    )


def test_fetch_live_snapshot_sorts_and_limits_events_for_timeline(monkeypatch):
    pod_obj = {
        "metadata": {"name": "mypod", "namespace": "default"},
        "spec": {},
        "status": {"phase": "Pending"},
    }

    events = {
        "kind": "List",
        "items": [
            {"reason": "A", "lastTimestamp": "2024-01-01T00:03:00Z"},
            {"reason": "B", "lastTimestamp": "2024-01-01T00:01:00Z"},
            {"reason": "C", "lastTimestamp": "2024-01-01T00:02:00Z"},
            {"reason": "D", "lastTimestamp": "2024-01-01T00:04:00Z"},
        ],
    }

    def fake_get(kind, name=None, **kwargs):
        if (kind, name) == ("pod", "mypod"):
            return copy.deepcopy(pod_obj)
        if (kind, name) == ("events", None):
            return copy.deepcopy(events)
        raise live_adapter.LiveIntrospectionError(f"not found: {kind}/{name}")

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    _, fetched_events, _, _, _ = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
        event_limit=2,
        event_chunk_size=50,
    )

    assert [e["reason"] for e in fetched_events] == ["A", "D"]
