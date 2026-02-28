from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class DNSResolutionFailureRule(FailureRule):
    """
    Detects DNS resolution failures occurring inside Pod containers.

    Signals:
    - Timeline event message contains DNS-related failure indicators
    (e.g., "dns", "cannot resolve", "lookup failed")

    Interpretation:
    The container attempts to resolve a hostname using cluster DNS,
    but resolution fails. As a result, the application cannot reach
    required services or external endpoints, leading to startup
    or runtime failure.

    Scope:
    - Container runtime / in-Pod networking phase
    - Deterministic (event-message based)
    - Captures application-visible DNS resolution failures

    Exclusions:
    - Does not directly verify CoreDNS health or Service availability
    - Does not diagnose CNI plugin failures
    - Does not inspect NetworkPolicy configuration
    - Does not analyze container logs beyond event messages
    """

    name = "DNSResolutionFailure"
    category = "Networking"
    priority = 31
    deterministic = True
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending", "Running"]

    container_states = ["terminated", "waiting"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        for e in timeline.raw_events:
            msg = (e.get("message") or "").lower()
            if "dns" in msg and ("failed" in msg or "cannot resolve" in msg):
                return True

        # Optional future container log analysis (placeholder)
        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        for c in container_statuses:
            state = c.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})
            if waiting or terminated:
                # For now only flag generic DNS failure in event
                continue
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_NETWORK_DEPENDENCY",
                    message="Container requires DNS resolution for external or cluster services",
                    role="runtime_context",
                ),
                Cause(
                    code="DNS_RESOLUTION_FAILURE",
                    message="DNS resolution failed inside Pod container",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="APPLICATION_STARTUP_FAILURE",
                    message="Application cannot start due to unresolved hostnames",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod cannot resolve DNS names",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Event message indicates DNS resolution failure",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {f"pod:{pod_name}": ["Pod failed to resolve DNS names"]},
            "likely_causes": [
                "CoreDNS unavailable or misconfigured",
                "Network policy blocks DNS traffic",
                "Node network misconfiguration",
                "Cluster DNS Service misconfiguration",
            ],
            "suggested_checks": [
                "kubectl get pods -n kube-system | grep coredns",
                "kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get svc -n kube-system",
                "Verify node connectivity to cluster DNS IP",
            ],
        }
