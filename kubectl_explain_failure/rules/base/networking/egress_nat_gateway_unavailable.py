from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class EgressNATGatewayUnavailableRule(FailureRule):
    """
    Detects loss of outbound Internet connectivity caused by a failed
    egress NAT gateway, Cloud NAT, egress appliance, or centralized
    outbound translation path.

    Real-world behavior:
    - Pods can often communicate with cluster services while external
      destinations fail.
    - TCP connections to public IPs timeout.
    - Route tables still point to NAT infrastructure.
    - NAT gateway may be unhealthy, detached, exhausted, deleted,
      unavailable, or blocked by infrastructure failure.
    - Common in AWS NAT Gateway, Azure NAT Gateway,
      GCP Cloud NAT, firewall appliances, egress gateways,
      transit gateways, and centralized outbound proxies.

    Exclusions:
    - DNS failures
    - NetworkPolicy denials
    - CNI failures
    - Pod sandbox creation failures
    - TLS/certificate failures
    - Application endpoint outages
    """

    name = "EgressNATGatewayUnavailable"
    category = "Networking"
    severity = "High"
    priority = 86
    deterministic = True

    phases = ["Running", "Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "pod",
            "route",
            "natgateway",
            "firewall",
            "gateway",
        ],
    }

    blocks = [
        "ExternalConnectivityFailure",
        "InternetReachabilityFailure",
    ]

    WINDOW_MINUTES = 20

    NAT_IDENTIFIERS = (
        "nat gateway",
        "natgateway",
        "cloud nat",
        "egress gateway",
        "egress-gateway",
        "egress gateway unavailable",
        "transit gateway",
        "internet gateway",
        "nva",
        "firewall appliance",
        "outbound gateway",
    )

    NAT_FAILURE_MARKERS = (
        "unavailable",
        "failed",
        "unhealthy",
        "not ready",
        "not available",
        "deleted",
        "detached",
        "route target unavailable",
        "connection tracking exhausted",
        "snat exhausted",
        "port allocation failed",
        "outbound connectivity lost",
        "egress unavailable",
        "failed health check",
    )

    EXTERNAL_CONNECTIVITY_MARKERS = (
        "i/o timeout",
        "context deadline exceeded",
        "connection timed out",
        "network is unreachable",
        "no route to host",
        "connection reset by peer",
        "dial tcp",
        "dial udp",
        "connect: connection refused",
    )

    CLUSTER_LOCAL_MARKERS = (
        "kubernetes.default",
        ".svc.cluster.local",
        "clusterip",
        "service reachable",
        "coredns ready",
        "kube-dns",
    )

    EXCLUSIONS = (
        "networkpolicy",
        "network policy",
        "failed to create pod sandbox",
        "failedcreatepodsandbox",
        "cni",
        "ipam",
        "dns lookup failed",
        "failed to resolve",
        "no such host",
        "certificate",
        "x509",
        "tls handshake",
        "imagepullbackoff",
        "errimagepull",
    )

    def _parse_timestamp(self, raw: Any):
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event):
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
        )

    def _message(self, event):
        return str(event.get("message") or "")

    def _reason(self, event):
        return str(event.get("reason") or "")

    def _occurrences(self, event):
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _recent_events(self, timeline: Timeline):
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _external_connectivity_failure(self, event):
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        if any(marker in text for marker in self.EXCLUSIONS):
            return False

        return any(marker in text for marker in self.EXTERNAL_CONNECTIVITY_MARKERS)

    def _nat_failure_event(self, event):
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        return any(i in text for i in self.NAT_IDENTIFIERS) and any(
            m in text for m in self.NAT_FAILURE_MARKERS
        )

    def _cluster_network_healthy(self, context):
        objects = context.get("objects", {})

        services = objects.get("service", {})
        endpoints = objects.get("endpoints", {})

        if services and endpoints:
            return True

        return False

    def _best_candidate(self, pod, timeline, context):
        recent = self._recent_events(timeline)

        external_failures = [
            e for e in recent if self._external_connectivity_failure(e)
        ]

        if not external_failures:
            return None

        nat_events = [e for e in recent if self._nat_failure_event(e)]

        nat_objects = []

        for kind in (
            "natgateway",
            "gateway",
            "firewall",
        ):
            nat_objects.extend(list(context.get("objects", {}).get(kind, {}).values()))

        nat_object_signal = len(nat_objects) > 0

        if not nat_events and not nat_object_signal:
            return None

        cluster_healthy = self._cluster_network_healthy(context)

        if not cluster_healthy:
            return None

        return {
            "external_failures": external_failures,
            "nat_events": nat_events,
            "nat_object_signal": nat_object_signal,
        }

    def matches(self, pod, events, context):
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "EgressNATGatewayUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get("metadata", {}).get(
            "namespace",
            "default",
        )

        representative = self._message(candidate["external_failures"][-1])

        failure_count = sum(
            self._occurrences(e) for e in candidate["external_failures"]
        )

        confidence = 0.92

        if candidate["nat_events"]:
            confidence = 0.98

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_REQUIRES_EXTERNAL_EGRESS",
                    message="Pod depends on outbound connectivity beyond the cluster",
                    role="runtime_context",
                ),
                Cause(
                    code="EGRESS_NAT_GATEWAY_UNAVAILABLE",
                    message="Centralized outbound NAT path is unavailable",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="EXTERNAL_CONNECTIONS_FAIL",
                    message="Outbound connections cannot reach external destinations",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "Egress NAT gateway is unavailable, preventing outbound Internet access"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (
                    f"Pod {namespace}/{pod_name} is experiencing "
                    f"external connectivity failures"
                ),
                f"Representative failure: {representative}",
                (
                    f"Observed {failure_count} outbound connectivity "
                    f"failure occurrence(s)"
                ),
                (
                    "Cluster-local networking appears functional while "
                    "external connectivity is failing"
                ),
                (
                    "Evidence points to centralized outbound NAT "
                    "infrastructure failure"
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    representative,
                ],
            },
            "likely_causes": [
                "Cloud NAT or NAT Gateway is unavailable",
                "NAT gateway route target is detached or deleted",
                "Egress gateway appliance is unhealthy",
                "Firewall/NVA outage is interrupting outbound translation",
                "SNAT port exhaustion has rendered outbound connectivity unavailable",
                "Transit gateway or centralized egress path failure",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Verify outbound connectivity from a test pod",
                "Inspect NAT gateway health and metrics",
                "Validate route tables for private subnets",
                "Check Cloud NAT / AWS NAT Gateway / Azure NAT Gateway status",
                "Inspect firewall or egress gateway health",
                "Review SNAT port utilization and exhaustion metrics",
            ],
        }
