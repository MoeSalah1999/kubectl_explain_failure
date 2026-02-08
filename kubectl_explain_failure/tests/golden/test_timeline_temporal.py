from kubectl_explain_failure.engine import explain_failure


def test_repeated_crashloop_detected():
    pod = {"metadata": {"name": "crashy"}, "status": {"phase": "Running"}}
    events = [{"reason": "BackOff"}] * 3

    result = explain_failure(pod, events, context={})

    assert "crashing" in result["root_cause"].lower()


def test_multiple_crashloop_containers():
    pod = {
        "metadata": {"name": "multi-crash"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"name": "c1", "state": {"waiting": {"reason": "CrashLoopBackOff"}}},
                {"name": "c2", "state": {"waiting": {"reason": "CrashLoopBackOff"}}},
            ],
        },
    }
    events = [{"reason": "BackOff"}, {"reason": "BackOff"}]

    result = explain_failure(pod, events, context={})
    assert "crashing" in result["root_cause"].lower()
    assert any("BackOff" in e for e in result["evidence"])
