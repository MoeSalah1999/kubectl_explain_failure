from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class IntermittentNetworkFlappingRule(FailureRule):
    """
    Detects intermittent network instability causing repeated readiness probe failures.

    Signals:
    - Repeated readiness probe failures within a short time window
    - Failures interspersed with successful probe recoveries

    Interpretation:
    The container becomes ready intermittently but repeatedly fails readiness
    checks shortly afterward. This often indicates unstable network connectivity
    to dependencies such as databases, upstream services, or DNS.

    Scope:
    - Temporal probe instability
    - Event frequency + recovery pattern
    """

    name = "IntermittentNetworkFlapping"
    category = "Temporal"
    priority = 65

    requires = {
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "ReadinessProbeFailure",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Frequent readiness failures
        readiness_failures = timeline.count(reason="Unhealthy")

        if readiness_failures < 3:
            return False

        # Ensure failures occur within a recent window
        recent_failures = timeline.events_within_window(
            10,
            reason="Unhealthy",
        )

        if len(recent_failures) < 3:
            return False

        # Verify that the container recovers between failures
        # (i.e., Ready events appear between failures)
        ready_events = timeline.count(reason="Ready")

        if ready_events == 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="READINESS_PROBE_CHECKING",
                    message="Readiness probe continuously checks container availability",
                    role="probe_context",
                ),
                Cause(
                    code="NETWORK_CONNECTIVITY_FLAPPING",
                    message="Intermittent network connectivity to required dependency",
                    blocking=False,
                    role="network_root",
                ),
                Cause(
                    code="READINESS_FLAPPING",
                    message="Container repeatedly alternates between ready and not-ready states",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Intermittent network connectivity causing readiness probe flapping",
            "confidence": 0.78,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} shows repeated readiness probe failures",
                "Readiness probe failures occur intermittently",
            ],
            "likely_causes": [
                "Intermittent connectivity to backend service",
                "DNS instability",
                "Network policy intermittently blocking traffic",
                "Upstream service temporarily unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name}",
                "Check service endpoints of dependent services",
                "Verify DNS resolution from the container",
            ],
            "blocking": False,
        }
