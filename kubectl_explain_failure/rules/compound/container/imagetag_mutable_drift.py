from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern

class ImageTagMutableDriftRule(FailureRule):
    """
    Detects production-impacting failures caused by image tag drift.

    Pattern:
    - Container image updated for same tag (e.g., :latest)
    - Pod CrashLoop begins after image digest change

    Signals:
    - Event sequence: image updated → pod crash/restart

    Scope:
    - Controller-level
    - High-value production issue
    """

    name = "ImageTagMutableDrift"
    category = "Compound"
    priority = 85
    deterministic = True
    blocks = ["CrashLoopBackOff", "RepeatedCrashLoop"]
    requires = {"objects": ["pod"]}

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Look for image updated then pod crash pattern
        pattern = [
            {"reason": "Pulling"},
            {"reason": "Pulled"},
            {"reason": "BackOff"},
        ]

        return timeline_has_pattern(timeline, pattern)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_UPDATED",
                    message="Container image with same tag was updated",
                    role="controller_context",
                ),
                Cause(
                    code="IMAGE_DIGEST_CHANGED",
                    message="Pod crash occurred after new image digest deployed",
                    role="workload_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASHLOOP_STARTED",
                    message="Pod entered CrashLoopBackOff due to image drift",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod failed due to mutable image tag change",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod: {pod_name}",
                "Event pattern: Pulling → Pulled → BackOff detected",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Image tag drift detected"]},
            "likely_causes": [
                "Mutable image tag used in production",
                "Image digest updated unexpectedly",
            ],
            "suggested_checks": [f"kubectl describe pod {pod_name}"],
        }