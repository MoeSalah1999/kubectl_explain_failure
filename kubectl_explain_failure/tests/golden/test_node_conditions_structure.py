from kubectl_explain_failure.context import _extract_node_conditions
from kubectl_explain_failure.model import load_json


def test_node_conditions_are_structured():

    node = load_json("tests/fixtures/node_disk_pressure.json")
    conds = _extract_node_conditions(node)

    assert "DiskPressure" in conds
    assert "status" in conds["DiskPressure"]
    assert "message" in conds["DiskPressure"]
