import json
import os

from kubectl_explain_failure.engine import explain_failure

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "golden",
    "compound",
    "container",
    "crashloop_oom",
    "input.json",
)


def load_fixture():
    with open(FIXTURE_PATH) as f:
        data = json.load(f)
    pod = data.get("pod", data)
    events = data.get("events", [])
    return pod, events


def test_crashloop_oom_blocks_base_rules():
    """
    Engine invariant:
    When CrashLoopOOMKilled matches,
    it must suppress:
      - CrashLoopBackOff
      - OOMKilled
    """
    pod, events = load_fixture()
    result = explain_failure(pod, events)

    assert result["resolution"]["winner"] == "CrashLoopOOMKilled"
    # Ensure blocked rules include the expected suppressed rules
    suppressed = result["resolution"].get("suppressed", [])
    assert "CrashLoopBackOff" in suppressed
    assert "OOMKilled" in suppressed


def test_blocking_metadata_is_correct():
    pod, events = load_fixture()
    result = explain_failure(pod, events)

    assert result["blocking"] is True
    suppressed = result["resolution"].get("suppressed", [])
    assert "CrashLoopBackOff" in suppressed
    assert "OOMKilled" in suppressed
