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
                            "valueFrom": {"secretKeyRef": {"name": "env-secret", "key": "pw"}},
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
        ("node", "node-a"): {"metadata": {"name": "node-a"}},
        ("replicaset", "rs-a"): {"metadata": {"name": "rs-a"}},
        ("serviceaccount", "sa-a"): {"metadata": {"name": "sa-a"}},
        ("secret", "pull-secret"): {"metadata": {"name": "pull-secret"}},
        ("secret", "app-secret"): {"metadata": {"name": "app-secret"}},
        ("secret", "env-secret"): {"metadata": {"name": "env-secret"}},
    }

    def fake_get(kind, name=None, **kwargs):
        key = (kind, name)
        if key not in table:
            raise AssertionError(f"unexpected kubectl request: {key}")
        return copy.deepcopy(table[key])

    monkeypatch.setattr(live_adapter, "_kubectl_get_json", fake_get)

    pod, events, context, warnings = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
    )

    assert pod["metadata"]["name"] == "mypod"
    assert events and events[0]["reason"] == "FailedScheduling"
    assert warnings == []

    objects = context["objects"]
    assert "pvc-a" in objects["pvc"]
    assert "pv-a" in objects["pv"]
    assert "sc-a" in objects["storageclass"]
    assert "node-a" in objects["node"]
    assert "rs-a" in objects["replicaset"]
    assert "sa-a" in objects["serviceaccount"]
    assert "pull-secret" in objects["secret"]
    assert "app-secret" in objects["secret"]
    assert "env-secret" in objects["secret"]


def test_fetch_live_snapshot_keeps_partial_context_on_fetch_failures(monkeypatch):
    pod_obj = {
        "metadata": {"name": "mypod", "namespace": "default"},
        "spec": {
            "nodeName": "node-a",
            "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "pvc-a"}}],
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

    pod, events, context, warnings = live_adapter.fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
    )

    assert pod["metadata"]["name"] == "mypod"
    assert events == []
    assert "node" in context["objects"]
    assert warnings
