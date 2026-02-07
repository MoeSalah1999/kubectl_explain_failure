from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json

def test_optional_objects_are_detected():

    pod = load_json("tests/fixtures/pending_pod.json")
    pvc = load_json("tests/fixtures/pvc_pending.json")

    context = {
        "objects": {
            "pvc": {pvc["metadata"]["name"]: pvc},
            "storageclass": {"standard": {"metadata": {"name": "standard"}}},
        }
    }

    result = explain_failure(pod, [], context)

    assert "PersistentVolumeClaim" in result["root_cause"]
