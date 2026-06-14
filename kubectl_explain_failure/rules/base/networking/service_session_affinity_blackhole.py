from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ServiceSessionAffinityBlackholeRule(FailureRule):
    """
    Detects a Service with ClientIP session affinity that continues routing
    traffic to stale/unhealthy backends because affinity mappings outlive
    endpoint health changes.

    Real-world behavior:
    - Service uses sessionAffinity=ClientIP
    - Endpoint(s) behind the Service become unready, terminating, drained,
      restarted, or disappear
    - Existing clients continue hitting a stale affinity target and observe
      connection failures, timeouts, resets, 5xx responses, or blackholed traffic
    - Other clients may continue working normally because they hash to healthy
      endpoints

    Exclusions:
    - Service has no ClientIP affinity
    - Complete Service outage affecting all endpoints equally
    - NetworkPolicy, CNI, DNS, ingress, or load balancer failures
    """

    name = "ServiceSessionAffinityBlackhole"
    category = "Networking"
    severity = "High"
    priority = 74
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "service",
            "endpoints",
            "endpointslice",
        ],
    }

    blocks = [
        "NetworkPolicyDenied",
        "CoreDNSUnavailable",
        "ServiceSelectorMismatch",
    ]

    WINDOW_MINUTES = 30

    CLIENT_ERROR_MARKERS = (
        "connection refused",
        "connection reset",
        "connection reset by peer",
        "i/o timeout",
        "io timeout",
        "timed out",
        "context deadline exceeded",
        "upstream connect error",
        "upstream request timeout",
        "502",
        "503",
        "504",
        "no healthy upstream",
        "transport endpoint",
        "broken pipe",
        "econnreset",
        "econnrefused",
    )

    NETWORK_EXCLUSIONS = (
        "networkpolicy",
        "network policy",
        "cni",
        "failedcreatepodsandbox",
        "dns",
        "no such host",
        "name resolution",
        "tls handshake",
        "certificate",
        "x509",
    )

    AFFINITY_TYPES = {
        "clientip",
    }

    ENDPOINT_FAILURE_REASONS = {
        "unhealthy",
        "killing",
        "backoff",
        "failed",
        "readinessprobefailed",
    }

    TERMINATING_REASONS = {
        "terminating",
        "shutdown",
        "deletion",
        "prestop",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        indexed = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _service_uses_clientip_affinity(self, service: dict[str, Any]) -> bool:
        affinity = service.get("spec", {}).get("sessionAffinity", "None")
        return str(affinity).lower() in self.AFFINITY_TYPES

    def _service_namespace(self, service: dict[str, Any]) -> str:
        return str(service.get("metadata", {}).get("namespace") or "default")

    def _service_name(self, service: dict[str, Any]) -> str:
        return str(service.get("metadata", {}).get("name") or "")

    def _pod_labels(self, pod: dict[str, Any]) -> dict[str, str]:
        return pod.get("metadata", {}).get("labels", {}) or {}

    def _service_selects_pod(
        self,
        service: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        selector = service.get("spec", {}).get("selector", {}) or {}
        if not selector:
            return False

        labels = self._pod_labels(pod)
        return all(labels.get(k) == v for k, v in selector.items())

    def _related_services(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        services = []

        for service in context.get("objects", {}).get("service", {}).values():
            if not isinstance(service, dict):
                continue

            if not self._service_uses_clientip_affinity(service):
                continue

            if self._service_selects_pod(service, pod):
                services.append(service)

        return services

    def _is_client_failure_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}

        if (
            involved.get("kind") == "Pod"
            and involved.get("name")
            and involved.get("name") != pod.get("metadata", {}).get("name")
        ):
            return False

        text = (f"{self._reason(event)} {self._message(event)}").lower()

        if any(x in text for x in self.NETWORK_EXCLUSIONS):
            return False

        return any(marker in text for marker in self.CLIENT_ERROR_MARKERS)

    def _service_endpoints_health(
        self,
        service: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, list[str]]:
        namespace = self._service_namespace(service)
        service_name = self._service_name(service)

        evidence: list[str] = []
        degraded = False

        endpoints = context.get("objects", {}).get("endpoints", {})

        for ep in endpoints.values():
            if not isinstance(ep, dict):
                continue

            meta = ep.get("metadata", {}) or {}
            if (
                meta.get("name") == service_name
                and meta.get("namespace", "default") == namespace
            ):
                for subset in ep.get("subsets", []) or []:
                    not_ready = subset.get("notReadyAddresses", []) or []
                    if not_ready:
                        degraded = True
                        evidence.append(f"{len(not_ready)} endpoint(s) are NotReady")

                addresses = sum(
                    len(subset.get("addresses", []) or [])
                    for subset in ep.get("subsets", []) or []
                )

                if addresses == 0:
                    return False, []

        slices = context.get("objects", {}).get("endpointslice", {})
        terminating_count = 0
        unready_count = 0
        ready_count = 0

        for es in slices.values():
            if not isinstance(es, dict):
                continue

            labels = es.get("metadata", {}).get("labels", {}) or {}
            if labels.get("kubernetes.io/service-name") != service_name:
                continue

            if es.get("metadata", {}).get("namespace", "default") != namespace:
                continue

            for endpoint in es.get("endpoints", []) or []:
                conditions = endpoint.get("conditions", {}) or {}

                if conditions.get("ready") is True:
                    ready_count += 1

                if conditions.get("ready") is False:
                    unready_count += 1

                if conditions.get("terminating") is True:
                    terminating_count += 1

        if unready_count:
            degraded = True
            evidence.append(f"{unready_count} EndpointSlice endpoint(s) are unready")

        if terminating_count:
            degraded = True
            evidence.append(
                f"{terminating_count} EndpointSlice endpoint(s) are terminating"
            )

        if ready_count == 0 and (unready_count or terminating_count):
            return False, []

        return degraded, evidence

    def _endpoint_failure_events(
        self,
        timeline: Timeline,
        service_name: str,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in self._ordered_recent_events(timeline):
            text = (f"{self._reason(event)} {self._message(event)}").lower()

            involved = event.get("involvedObject", {}) or {}

            service_hint = service_name.lower() in text

            endpoint_related = involved.get("kind", "").lower() in {
                "pod",
                "endpoints",
                "endpointslice",
            }

            if not (service_hint or endpoint_related):
                continue

            if (
                any(x in text for x in self.ENDPOINT_FAILURE_REASONS)
                or any(x in text for x in self.TERMINATING_REASONS)
                or "readiness probe failed" in text
            ):
                matches.append(event)

        return matches

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        services = self._related_services(pod, context)
        if not services:
            return None

        client_failures = [
            e
            for e in self._ordered_recent_events(timeline)
            if self._is_client_failure_event(e, pod)
        ]

        if not client_failures:
            return None

        for service in services:
            degraded, endpoint_evidence = self._service_endpoints_health(
                service,
                context,
            )

            endpoint_events = self._endpoint_failure_events(
                timeline,
                self._service_name(service),
            )

            if not degraded and not endpoint_events:
                continue

            duration_seconds = timeline.duration_between(
                lambda e: (self._is_client_failure_event(e, pod))
            )

            return {
                "service": service,
                "client_failures": client_failures,
                "endpoint_events": endpoint_events,
                "endpoint_evidence": endpoint_evidence,
                "duration_seconds": duration_seconds,
            }

        return None

    def matches(self, pod, events, context) -> bool:
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
        if not isinstance(timeline, Timeline):
            raise ValueError(
                "ServiceSessionAffinityBlackhole requires Timeline context"
            )

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "ServiceSessionAffinityBlackhole explain() called without match"
            )

        service = candidate["service"]
        service_name = self._service_name(service)
        namespace = self._service_namespace(service)

        representative_failure = self._message(candidate["client_failures"][-1])

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_CLIENTIP_AFFINITY",
                    message="Service uses ClientIP session affinity",
                    role="runtime_context",
                ),
                Cause(
                    code="AFFINITY_POINTS_TO_STALE_ENDPOINT",
                    message="Existing affinity mapping points to an unhealthy or terminating backend",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CLIENT_REQUESTS_BLACKHOLED",
                    message="Requests continue reaching the stale endpoint until affinity expires",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Service {namespace}/{service_name} uses ClientIP session affinity",
            f"Representative client failure: {representative_failure}",
            *candidate["endpoint_evidence"],
        ]

        if candidate["endpoint_events"]:
            evidence.append(
                f"Observed {sum(self._occurrences(e) for e in candidate['endpoint_events'])} endpoint degradation event occurrence(s)"
            )

        if candidate["duration_seconds"]:
            evidence.append(
                f"Symptoms persisted for {candidate['duration_seconds'] / 60:.1f} minutes"
            )

        confidence = 0.92
        if candidate["endpoint_events"] and candidate["endpoint_evidence"]:
            confidence = 0.98

        return {
            "rule": self.name,
            "root_cause": (
                "ClientIP session affinity is pinning traffic to a stale "
                "or unhealthy backend endpoint"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                f"service:{service_name}": list(
                    dict.fromkeys(candidate["endpoint_evidence"])
                ),
                f"pod:{pod.get('metadata', {}).get('name', '<unknown>')}": [
                    representative_failure
                ],
            },
            "likely_causes": [
                "A backend pod became unready after affinity entries were established",
                "An endpoint is terminating while clients remain pinned to it",
                "Session affinity timeout is longer than backend lifecycle changes",
                "Rolling update removed or drained endpoints while affinity mappings remained active",
                "A subset of clients is routed to stale backends while others continue working",
            ],
            "suggested_checks": [
                f"kubectl describe service {service_name} -n {namespace}",
                f"kubectl get endpoints {service_name} -n {namespace} -o yaml",
                (
                    f"kubectl get endpointslices -n {namespace} "
                    f"-l kubernetes.io/service-name={service_name}"
                ),
                (
                    f"kubectl get service {service_name} -n {namespace} "
                    "-o jsonpath='{.spec.sessionAffinity}'"
                ),
                "Inspect readiness transitions and rollout history of backend pods",
                "Temporarily disable ClientIP affinity or reduce affinity timeout to validate the hypothesis",
            ],
        }
