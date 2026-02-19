from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NetworkPolicyBlockedRule(FailureRule):
    """
    Pod Running
    → Readiness failing
    → NetworkPolicy present
    → Traffic denied to required Service
    """

    name = "NetworkPolicyBlocked"
    category = "Compound"
    priority = 57
    blocks = [
        "ReadinessProbeFailure",
        "DNSResolutionFailure",
        "CNIPluginFailure",
    ]
    requires = {
        "objects": ["networkpolicy"],
        "context": ["timeline"],
    }
    phases = ["Running"]

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        policies = objects.get("networkpolicy", {})

        if not policies:
            return False

        # Readiness failing
        readiness_failing = False
        for cs in pod.get("status", {}).get("containerStatuses", []):
            if not cs.get("ready", True):
                readiness_failing = True
                break

        if not readiness_failing:
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # Detect connection-related failures (but not DNS errors)
        connection_blocked = any(
            "connection refused" in e.get("message", "").lower()
            or "i/o timeout" in e.get("message", "").lower()
            or "connection timed out" in e.get("message", "").lower()
            for e in timeline.raw_events
        )

        if not connection_blocked:
            return False

        # Ensure no DNS resolution failure pattern (let DNS rule handle that)
        dns_pattern = any(
            "no such host" in e.get("message", "").lower() for e in timeline.raw_events
        )

        if dns_pattern:
            return False

        return True

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        policy_name = next(iter(objects.get("networkpolicy", {})), "<unknown>")
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="NETWORK_POLICY_PRESENT",
                    message="NetworkPolicy applies to this Pod",
                    blocking=True,
                    role="network_policy_root",
                ),
                Cause(
                    code="TRAFFIC_DENIED",
                    message="Ingress/Egress traffic denied by policy",
                    blocking=True,
                    role="network_enforcement",
                ),
                Cause(
                    code="READINESS_FAILURE",
                    message="Container readiness failing due to connectivity issues",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "NetworkPolicy blocks required traffic causing readiness failure",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"NetworkPolicy {policy_name} present",
                "Connection timeout/refused events detected",
                "Container readiness = False",
            ],
            "object_evidence": {
                f"networkpolicy:{policy_name}": ["Policy may deny traffic"],
                f"pod:{pod_name}": ["Readiness probe failing"],
            },
            "suggested_checks": [
                f"kubectl describe networkpolicy {policy_name}",
                "Verify ingress/egress rules match Pod labels",
                "Test connectivity from inside Pod",
            ],
            "blocking": True,
        }
