import copy

from kubectl_explain_failure.live_adapter import (
    LiveIntrospectionError,
    fetch_live_snapshot,
)


class FakeProvider:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def get_json(self, kind, name=None, **kwargs):
        self.calls.append((kind, name, kwargs.get("namespace")))
        key = (kind, name)
        if key not in self.table:
            raise LiveIntrospectionError(f"not found: {kind}/{name}")
        return copy.deepcopy(self.table[key])


def test_fetch_live_snapshot_uses_custom_provider_for_discovery_pipeline():
    table = {
        ("pod", "mypod"): {
            "metadata": {
                "name": "mypod",
                "namespace": "default",
                "ownerReferences": [{"kind": "ReplicaSet", "name": "rs-a"}],
            },
            "spec": {
                "nodeName": "node-a",
                "serviceAccountName": "sa-a",
                "volumes": [
                    {"name": "data", "persistentVolumeClaim": {"claimName": "pvc-a"}}
                ],
            },
            "status": {"phase": "Pending"},
        },
        ("events", None): {
            "kind": "List",
            "items": [
                {"reason": "FailedScheduling", "lastTimestamp": "2024-01-01T00:00:00Z"}
            ],
        },
        ("pvc", "pvc-a"): {
            "metadata": {"name": "pvc-a"},
            "spec": {"volumeName": "pv-a", "storageClassName": "sc-a"},
            "status": {"phase": "Pending"},
        },
        ("pv", "pv-a"): {"metadata": {"name": "pv-a"}},
        ("storageclass", "sc-a"): {"metadata": {"name": "sc-a"}},
        ("node", "node-a"): {"metadata": {"name": "node-a"}},
        ("replicaset", "rs-a"): {
            "metadata": {
                "name": "rs-a",
                "ownerReferences": [{"kind": "Deployment", "name": "deploy-a"}],
            }
        },
        ("deployment", "deploy-a"): {"metadata": {"name": "deploy-a"}},
        ("serviceaccount", "sa-a"): {"metadata": {"name": "sa-a"}},
    }

    provider = FakeProvider(table)
    pod, events, context, warnings, live_metadata = fetch_live_snapshot(
        pod_name="mypod",
        namespace="default",
        timeout_seconds=5,
        provider=provider,
    )

    assert pod["metadata"]["name"] == "mypod"
    assert events and events[0]["reason"] == "FailedScheduling"
    assert warnings == []
    assert live_metadata["completeness"]["missing_total"] == 0
    assert context["owner"]["metadata"]["name"] == "deploy-a"

    called_pairs = {(kind, name) for kind, name, _ in provider.calls}
    assert ("pod", "mypod") in called_pairs
    assert ("events", None) in called_pairs
    assert ("pvc", "pvc-a") in called_pairs
    assert ("pv", "pv-a") in called_pairs
    assert ("storageclass", "sc-a") in called_pairs
    assert ("node", "node-a") in called_pairs
    assert ("replicaset", "rs-a") in called_pairs
    assert ("deployment", "deploy-a") in called_pairs
    assert ("serviceaccount", "sa-a") in called_pairs
