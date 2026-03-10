from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class RuntimeClassNotFoundRule(FailureRule):
    """
    Detects Pod startup failures caused by a missing RuntimeClass.

    Signals:
    - Pod.spec.runtimeClassName is set
    - Referenced RuntimeClass object does not exist
    - Pod events indicate runtime class resolution failure

    Interpretation:
    The Pod specifies a runtimeClassName but the corresponding
    RuntimeClass resource cannot be found in the cluster. This
    prevents the container runtime from creating the Pod sandbox.

    Scope:
    - Scheduling/runtime initialization failure
    - Deterministic when RuntimeClass object is absent
    """

    name = "RuntimeClassNotFound"
    category = "Scheduling"
    priority = 15
    deterministic = True

    blocks = []

    requires = {
        "pod": True,
        "objects": ["runtimeclass"],
    }

    def matches(self, pod, events, context) -> bool:
        spec = pod.get("spec", {})
        runtime_class_name = spec.get("runtimeClassName")

        if not runtime_class_name:
            return False

        runtimeclasses = context.get("objects", {}).get("runtimeclass", {})

        # RuntimeClass exists → not this rule
        if runtime_class_name in runtimeclasses:
            return False

        timeline = build_timeline(events)

        # Look for failure signals in recent events
        recent_events = timeline.events_within_window(15)

        for e in recent_events:
            msg = (e.get("message") or "").lower()
            reason = (e.get("reason") or "").lower()

            if "runtimeclass" in msg and "not found" in msg:
                return True

            if reason in ("failedcreatepodsandbox", "failedscheduling"):
                if "runtimeclass" in msg:
                    return True

        # Deterministic fallback: runtimeClass missing
        return True

    def explain(self, pod, events, context):
        spec = pod.get("spec", {})
        runtime_class_name = spec.get("runtimeClassName")

        timeline = build_timeline(events)

        evidence_msgs = []

        for e in timeline.events_within_window(15):
            msg = e.get("message")
            if not msg:
                continue
            if "runtimeclass" in msg.lower():
                evidence_msgs.append(msg)

        chain = CausalChain(
            causes=[
                Cause(
                    code="RUNTIMECLASS_REFERENCED",
                    message="Pod specifies a runtimeClassName",
                    role="scheduler_context",
                ),
                Cause(
                    code="RUNTIMECLASS_NOT_FOUND",
                    message="Referenced RuntimeClass does not exist in the cluster",
                    role="scheduler_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_CREATION_FAILED",
                    message="Container runtime cannot create Pod sandbox without a valid RuntimeClass",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        return {
            "rule": self.name,
            "root_cause": "Pod references a RuntimeClass that does not exist",
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod.spec.runtimeClassName={runtime_class_name}",
                "Referenced RuntimeClass object missing from cluster",
                *evidence_msgs[:2],
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"runtimeClassName={runtime_class_name}",
                    "RuntimeClass resource not found",
                ]
            },
            "likely_causes": [
                "RuntimeClass resource was never created",
                "RuntimeClass name typo in Pod spec",
                "RuntimeClass deleted while workload still references it",
                "Cluster runtime configuration mismatch",
            ],
            "suggested_checks": [
                f"kubectl get runtimeclass {runtime_class_name}",
                "kubectl get runtimeclass",
                f"kubectl describe pod {pod_name}",
                "Verify runtimeClassName in workload manifest",
            ],
        }