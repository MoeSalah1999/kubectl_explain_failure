import os
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.model import load_json

HERE = os.path.dirname(__file__)
FIXTURES = os.path.abspath(os.path.join(HERE, "..", "fixtures"))

def test_optional_objects_are_detected():

    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES, "pvc_pending.json"))

    context = {
        "objects": {
            "pvc": {pvc["metadata"]["name"]: pvc},
            "storageclass": {"standard": {"metadata": {"name": "standard"}}},
        }
    }

    result = explain_failure(pod, [], context)

    assert "PersistentVolumeClaim" in result["root_cause"]
