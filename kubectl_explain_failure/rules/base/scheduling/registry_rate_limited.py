from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline, timeline_has_event

class RegistryRateLimitedRule(FailureRule):
    """
    Detects failures caused by container registry throttling or rate limiting (HTTP 429).

    Pattern:
    - Pod events include 'Pulling', 'Failed', with source='registry' and reason='TooManyRequests'

    Signals:
    - Pod fails to pull image due to rate limiting

    Scope:
    - Scheduler / Single-pod failure
    - Can trigger ImagePullBackOff

    Notes:
    - Typically caused by excessive concurrent pulls or registry throttling
    """

    name = "RegistryRateLimited"
    category = "Scheduling"
    priority = 65
    deterministic = True
    blocks = ["ImagePullBackOff"]
    requires = {}

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_event(timeline, kind="Image", phase="Failure", source="registry")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_BLOCKED_BY_REGISTRY",
                    message="Pod scheduling blocked due to registry throttling",
                    role="scheduling_context",
                ),
                Cause(
                    code="REGISTRY_429",
                    message="Registry returned HTTP 429 TooManyRequests",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_FAILED",
                    message="Pod failed to pull image due to rate limiting",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod failed due to registry rate limiting (HTTP 429)",
            "confidence": 0.92,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Pod: {pod_name}",
                "Event reason contains TooManyRequests / HTTP 429",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Registry rate limit encountered"]},
            "likely_causes": [
                "Registry throttling",
                "Excessive concurrent pulls",
            ],
            "suggested_checks": [f"kubectl describe pod {pod_name}"],
        }