from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_event

class ImagePolicyWebhookRejectedRule(FailureRule):
    """
    Detects container failures caused by image policy webhook rejection at runtime.

    Signals:
    - Pod events where the image pull fails due to policy rejection
    - Admission succeeded, but runtime webhook rejected the image

    Interpretation:
    - The container runtime cannot pull or start the container because the
    image was rejected by an admission/webhook policy.
    - Typically occurs due to non-compliant images, unauthorized registries, or
    signature/policy mismatches.

    Scope:
    - Container runtime / Kubelet phase
    - Phases: Pending
    - Deterministic (state-based)
    - Blocks downstream ImagePullBackOff failures

    Exclusions:
    - Does not cover generic ImagePullBackOff caused by network issues,
    authentication errors, or missing images
    """

    name = "ImagePolicyWebhookRejected"
    category = "Admission"
    priority = 65
    deterministic = True
    blocks = ["ImagePullBackOff"]
    requires = {}

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        # Look specifically for webhook rejection events
        return timeline_has_event(timeline, kind="Image", phase="Failure", source="image-policy-webhook")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="POLICY_EVALUATION",
                    message="Image policy was evaluated by webhook",
                    role="admission_context",
                ),
                Cause(
                    code="WEBHOOK_REJECTED",
                    message="Image policy webhook rejected the pod image",
                    role="admission_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_FAILED",
                    message="Pod failed to pull image due to policy enforcement",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod image rejected by runtime policy webhook",
            "confidence": 0.94,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod: {pod_name}",
                "Event source indicates image-policy-webhook rejection",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Image rejected by webhook"]},
            "likely_causes": [
                "Image does not meet cluster policy requirements",
                "Unauthorized image registry or signature",
            ],
            "suggested_checks": [f"kubectl describe pod {pod_name}"],
        }