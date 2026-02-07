from kubectl_explain_failure.engine import explain_failure


def test_repeated_crashloop_detected():
    pod = {"metadata": {"name": "crashy"}, "status": {"phase": "Running"}}
    events = [{"reason": "BackOff"}] * 3

    result = explain_failure(pod, events, context={})

    assert "crashing" in result["root_cause"].lower()
