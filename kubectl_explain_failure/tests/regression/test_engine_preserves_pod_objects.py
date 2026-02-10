
from kubectl_explain_failure.engine import explain_failure


def test_engine_preserves_pod_level_objects_for_compound_rules():
    """
    Regression test for engine bug:
    pod-level objects (e.g. PVCs) were dropped during normalize_context(),
    causing compound rules with requires={"objects": [...]} to never fire.
    """

    pod = {
        "metadata": {"name": "test-pod"},
        "status": {"phase": "Pending"},
        "objects": {
            "pvc": {
                "data-pvc": {
                    "metadata": {"name": "data-pvc"},
                    "status": {"phase": "Pending"},
                }
            }
        },
        "blocking_pvc": {
            "metadata": {"name": "data-pvc"},
            "status": {"phase": "Pending"},
        },
        "events": [
            {
                "reason": "ImagePullBackOff",
                "message": "Back-off pulling image",
                "type": "Warning",
            }
        ],
    }

    events = pod["events"]

    result = explain_failure(pod, events, context=None)

    # --- ASSERTIONS ---

    # 1. Engine must not fall back to single rules
    assert result["root_cause"] != "Container image could not be pulled"

    # 2. Compound PVC → ImagePull rule MUST win
    assert (
        "PVC" in result["root_cause"] and "image" in result["root_cause"].lower()
    ), result["root_cause"]

    # 3. Engine must treat this as a blocking failure
    assert result.get("blocking") is True


def test_engine_preserves_pod_level_objects_even_when_no_rule_matches():
    """
    Regression test guarding object-graph normalization.

    Ensures that:
    - pod-level objects survive normalize_context
    - engine does NOT misfire unrelated rules
    - engine safely returns Unknown when no rule matches

    This test intentionally does NOT assume any Secret compound rule exists.
    """

    pod = {
        "metadata": {"name": "secret-imagepull-pod"},
        "status": {"phase": "Pending"},
        "objects": {
            "secret": {
                "regcred": {
                    "metadata": {"name": "regcred"},
                    "type": "kubernetes.io/dockerconfigjson",
                }
            }
        },
        "events": [
            {
                "reason": "Failed",
                "message": 'Failed to pull image "private.registry/app"',
                "type": "Warning",
            }
        ],
    }

    events = pod["events"]

    result = explain_failure(pod, events, context=None)

    # --- ASSERTIONS ---

    # 1. Engine must return a valid explanation
    assert isinstance(result, dict)

    # 2. No incorrect fallback to ImagePullBackOff rule
    assert result["root_cause"] != "Container image could not be pulled"

    # 3. No false positives — Unknown is correct when no rule matches
    assert result["root_cause"] == "Unknown"
