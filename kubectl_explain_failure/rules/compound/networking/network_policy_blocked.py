from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NetworkPolicyBlockedRule(FailureRule):
    """
    Detects Pods that are Running but failing readiness checks
    due to traffic being denied by an applicable NetworkPolicy.

    Signals:
    - Pod phase is Running
    - At least one container has ready=False
    - NetworkPolicy objects present selecting the Pod
    - Timeline includes connection timeout/refused events
    - No DNS resolution failure pattern detected

    Interpretation:
    A NetworkPolicy applies to the Pod and denies required
    ingress or egress traffic. As a result, connectivity to
    dependent Services fails, causing readiness probes to
    fail while the Pod remains in Running phase.

    Scope:
    - Policy enforcement layer (NetworkPolicy + traffic control)
    - Deterministic (object-state + event correlation based)
    - Acts as a compound check to suppress generic readiness,
    DNS, or CNI blame when policy denial is the true cause

    Exclusions:
    - Does not include DNS resolution failures
    - Does not include CNI plugin initialization errors
    - Does not include container-level crashes unrelated to networking
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
                    code="NETWORK_POLICY_APPLIES",
                    message="NetworkPolicy selects this Pod and connection failures detected",
                    role="policy_context",
                ),
                Cause(
                    code="NETWORK_POLICY_TRAFFIC_DENIED",
                    message="NetworkPolicy denies required ingress or egress traffic",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="READINESS_PROBE_FAILURE",
                    message="Container readiness failing due to connectivity denial",
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
