import os

from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.model import load_json

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_legacy_pvc_context_is_normalized():
    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    pvc = load_json(os.path.join(FIXTURES, "pvc_pending.json"))

    result = explain_failure(pod, [], context=normalize_context({"pvc": pvc}))

    assert "persistentvolumeclaim" in result["root_cause"].lower()
    assert result["confidence"] > 0


def test_legacy_node_context_is_normalized():
    pod = load_json(os.path.join(FIXTURES, "pending_pod.json"))
    node = load_json(os.path.join(FIXTURES, "node_disk_pressure.json"))

    result = explain_failure(pod, [], context=normalize_context({"node": node}))

    assert "disk pressure" in result["root_cause"].lower()
