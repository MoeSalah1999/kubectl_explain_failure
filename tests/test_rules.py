from explain_failure import explain_failure, load_json, normalize_events

def test_pvc_not_bound():
    pod = load_json("fixtures/pod_pending.json")
    pvc = load_json("fixtures/pvc_pending.json")
    events = []

    result = explain_failure(pod, events, context={"pvc": pvc})
    assert result["root_cause"].startswith("Pod is blocked by unbound")

def test_node_disk_pressure():
    pod = load_json("fixtures/pod_pending.json")
    node = load_json("fixtures/node_disk_pressure.json")
    events = []

    result = explain_failure(pod, events, context={"node": node})
    assert "disk pressure" in result["root_cause"].lower()

def test_configmap_missing():
    pod = load_json("fixtures/pod_pending.json")
    events = normalize_events(load_json("fixtures/events_configmap_missing.json"))

    result = explain_failure(pod, events)
    assert "ConfigMap" in result["root_cause"]
