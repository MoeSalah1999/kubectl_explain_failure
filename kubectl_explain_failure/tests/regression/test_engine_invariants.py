from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure, normalize_context
from kubectl_explain_failure.timeline import build_timeline


def test_engine_always_sets_blocking_boolean():
    """
    Engine-level invariant regression test.

    Contract:
    - explain_failure() MUST always return a 'blocking' field
    - 'blocking' MUST be a boolean (never None, never missing)

    This must hold even when:
    - no rules fire
    - events are empty
    - pod is minimal
    """

    pod = {
        "metadata": {
            "name": "dummy-pod",
            "namespace": "default",
        },
        "status": {
            "phase": "Running",
        },
    }

    events = []

    context = build_context(
        type(
            "Args",
            (),
            {
                "pvc": None,
                "pvcs": None,
                "pv": None,
                "storageclass": None,
                "node": None,
                "serviceaccount": None,
                "secret": None,
                "replicaset": None,
                "deployment": None,
                "statefulsets": None,
                "daemonsets": None,
            },
        )()
    )

    context["timeline"] = build_timeline(events)
    context = normalize_context(context)

    result = explain_failure(pod, events, context=context)

    assert isinstance(result, dict), "Engine must return a dict"

    assert (
        "blocking" in result
    ), "Engine invariant violated: 'blocking' field missing from result"

    assert isinstance(result["blocking"], bool), (
        f"Engine invariant violated: 'blocking' must be bool, "
        f"got {type(result['blocking']).__name__}"
    )
