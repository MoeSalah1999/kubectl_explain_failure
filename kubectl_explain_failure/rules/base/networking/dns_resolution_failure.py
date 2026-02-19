from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class DNSResolutionFailureRule(FailureRule):
    """
    Detects DNS resolution failures inside Pod containers.
    Triggered by:
      - Container in CrashLoop
      - Event message (or logs, if adapter present) shows DNS resolution failure
    For now event-based detection.
    """

    name = "DNSResolutionFailure"
    category = "Networking"
    priority = 31

    requires = {"pod": True}

    phases = ["Pending", "Running"]

    container_states = ["terminated", "waiting"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            reason = e.get("reason", "")
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
                    code="DNS_RESOLUTION_FAILURE",
                    message="DNS resolution failed inside Pod container",
                    blocking=True,
                )
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
            ],
            "suggested_checks": [
                "kubectl get pods -n kube-system | grep coredns",
                "kubectl describe pod {pod_name} -n {namespace}",
                "Verify node network connectivity to DNS server",
            ],
        }
