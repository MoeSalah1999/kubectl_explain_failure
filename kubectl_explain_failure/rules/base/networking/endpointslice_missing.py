from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class EndpointSliceMissingRule(FailureRule):
    """
    Detects selector-based Services that should have EndpointSlices but do not.

    Real-world behavior:
    - the Kubernetes control plane normally creates EndpointSlices for Services
      that have a selector
    - modern Service routing depends on EndpointSlices as the primary backend
      source of truth
    - if a Service has backend endpoints but no matching EndpointSlice objects,
      traffic can fail even though the Service itself exists
    """

    name = "EndpointSliceMissing"
    category = "Networking"
    priority = 46
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["service", "endpointslice"],
    }

    optional_objects = ["endpoints"]

    blocks = ["CrashLoopBackOff"]

    WINDOW_MINUTES = 20
    FAILURE_MARKERS = (
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "no route to host",
        "upstream unavailable",
        "service unavailable",
    )
    SERVICE_HOST_RE = re.compile(
        r"(?:(?:https?|tcp)://)?(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+){0,4})",
        re.IGNORECASE,
    )

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
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _service_aliases(
        self,
        services: dict[str, Any],
        namespace: str,
    ) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for service_name in services:
            normalized = str(service_name).lower()
            aliases[normalized] = service_name
            aliases[f"{normalized}.{namespace}"] = service_name
            aliases[f"{normalized}.{namespace}.svc"] = service_name
            aliases[f"{normalized}.{namespace}.svc.cluster.local"] = service_name
        return aliases

    def _extract_service_refs_from_text(
        self,
        text: str,
        aliases: dict[str, str],
    ) -> list[str]:
        refs: list[str] = []
        lowered = str(text or "").lower()

        for match in self.SERVICE_HOST_RE.finditer(lowered):
            host = match.group("host")
            if host in aliases:
                refs.append(aliases[host])

        return refs

    def _configured_service_refs(
        self,
        pod: dict[str, Any],
        aliases: dict[str, str],
    ) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}

        for container in pod.get("spec", {}).get("containers", []) or []:
            container_name = str(container.get("name", "")).strip() or "<unknown>"

            for env in container.get("env", []) or []:
                value = env.get("value")
                if not isinstance(value, str):
                    continue
                for service_name in self._extract_service_refs_from_text(
                    value, aliases
                ):
                    refs.setdefault(service_name, []).append(
                        f"env {container_name}:{env.get('name', '<env>')}={value}"
                    )

            for field_name in ("command", "args"):
                for item in container.get(field_name, []) or []:
                    if not isinstance(item, str):
                        continue
                    for service_name in self._extract_service_refs_from_text(
                        item, aliases
                    ):
                        refs.setdefault(service_name, []).append(
                            f"{field_name} {container_name}:{item}"
                        )

        return refs

    def _matching_endpoint_slices(
        self,
        endpoint_slices: dict[str, Any],
        service_name: str,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for slice_obj in endpoint_slices.values():
            labels = slice_obj.get("metadata", {}).get("labels", {})
            if labels.get("kubernetes.io/service-name") == service_name:
                matches.append(slice_obj)
        return matches

    def _ready_endpoint_addresses(
        self,
        endpoints: dict[str, Any],
        service_name: str,
    ) -> list[str]:
        endpoint = endpoints.get(service_name, {})
        addresses: list[str] = []
        for subset in endpoint.get("subsets", []) or []:
            for address in subset.get("addresses", []) or []:
                ip = address.get("ip")
                if isinstance(ip, str) and ip:
                    addresses.append(ip)
        return addresses

    def _controller_failure_mentions_service(
        self,
        event: dict[str, Any],
        service_name: str,
    ) -> bool:
        message = str(event.get("message", "")).lower()
        if "endpointslice" not in message:
            return False
        return service_name.lower() in message

    def _is_service_failure_event(
        self,
        event: dict[str, Any],
        service_name: str,
        aliases: dict[str, str],
    ) -> bool:
        message = str(event.get("message", ""))
        lowered = message.lower()

        if self._controller_failure_mentions_service(event, service_name):
            return True

        if not any(marker in lowered for marker in self.FAILURE_MARKERS):
            return False

        return service_name in self._extract_service_refs_from_text(message, aliases)

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        objects = context.get("objects", {})
        services = objects.get("service", {})
        endpoint_slices = objects.get("endpointslice", {})
        endpoints = objects.get("endpoints", {})

        if not services or endpoint_slices is None:
            return None

        namespace = str(pod.get("metadata", {}).get("namespace", "default")).lower()
        aliases = self._service_aliases(services, namespace)
        configured_refs = self._configured_service_refs(pod, aliases)
        recent_events = self._ordered_recent_events(timeline)
        if not recent_events:
            return None

        best: dict[str, Any] | None = None

        for service_name, service in services.items():
            spec = service.get("spec", {})
            if spec.get("type") == "ExternalName":
                continue
            if not spec.get("selector"):
                continue
            if spec.get("clusterIP") == "None":
                continue

            matching_slices = self._matching_endpoint_slices(
                endpoint_slices, service_name
            )
            if matching_slices:
                continue

            ready_addresses = self._ready_endpoint_addresses(endpoints, service_name)

            supporting_events = [
                event
                for event in recent_events
                if self._is_service_failure_event(event, service_name, aliases)
            ]

            controller_events = [
                event
                for event in supporting_events
                if self._controller_failure_mentions_service(event, service_name)
            ]

            if not ready_addresses and not controller_events:
                continue

            if not supporting_events and not configured_refs.get(service_name):
                continue

            candidate = {
                "service_name": service_name,
                "ready_addresses": ready_addresses,
                "supporting_events": supporting_events,
                "controller_events": controller_events,
                "config_sources": list(
                    dict.fromkeys(configured_refs.get(service_name, []))
                ),
                "dominant_message": max(
                    (str(event.get("message", "")) for event in supporting_events),
                    key=lambda message: sum(
                        self._occurrences(event)
                        for event in supporting_events
                        if str(event.get("message", "")) == message
                    ),
                    default="",
                ),
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                len(best["ready_addresses"]),
                sum(self._occurrences(event) for event in best["controller_events"]),
                sum(self._occurrences(event) for event in best["supporting_events"]),
                len(best["config_sources"]),
            )
            candidate_key = (
                len(candidate["ready_addresses"]),
                sum(
                    self._occurrences(event) for event in candidate["controller_events"]
                ),
                sum(
                    self._occurrences(event) for event in candidate["supporting_events"]
                ),
                len(candidate["config_sources"]),
            )
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline, context) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("EndpointSliceMissing requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("EndpointSliceMissing explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        service_name = candidate["service_name"]
        ready_addresses = candidate["ready_addresses"]
        supporting_occurrences = sum(
            self._occurrences(event) for event in candidate["supporting_events"]
        )

        confidence = 0.93
        if ready_addresses:
            confidence += 0.02
        if candidate["controller_events"]:
            confidence += 0.01

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_REQUIRES_ENDPOINTSLICES",
                    message=(
                        f"Selector-based Service '{service_name}' should have controller-managed EndpointSlices"
                    ),
                    role="service_context",
                ),
                Cause(
                    code="ENDPOINTSLICE_MISSING",
                    message=(
                        f"No EndpointSlice objects are linked to Service '{service_name}'"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SERVICE_BACKEND_DISCOVERY_INCOMPLETE",
                    message=(
                        "Service backend routing metadata is incomplete even though the Service exists"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Service '{service_name}' is selector-based but no EndpointSlice objects with label kubernetes.io/service-name={service_name} were found",
            f"Observed {supporting_occurrences} recent failure signal(s) referencing Service '{service_name}' within the last {self.WINDOW_MINUTES} minutes",
        ]
        if ready_addresses:
            evidence.append(
                f"Legacy Endpoints for Service '{service_name}' still contain ready backend address(es): {', '.join(ready_addresses[:3])}"
            )
        if candidate["controller_events"]:
            evidence.append(
                "Recent events also mention EndpointSlice sync or controller failure for the Service"
            )
        if candidate["config_sources"]:
            evidence.append(
                "Workload configuration explicitly references the affected Service"
            )

        object_evidence = {
            f"service:{service_name}": [
                "No matching EndpointSlice objects found for the Service",
            ],
            f"pod:{pod_name}": [
                candidate["dominant_message"],
            ],
        }
        if ready_addresses:
            object_evidence[f"service:{service_name}"].append(
                "Legacy Endpoints still list ready backend addresses"
            )
        for source in candidate["config_sources"][:2]:
            object_evidence[f"pod:{pod_name}"].append(source)

        return {
            "root_cause": (
                f"Service '{service_name}' is missing EndpointSlice objects needed for backend discovery"
            ),
            "confidence": min(0.97, confidence),
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The EndpointSlice controller is unhealthy or cannot reconcile the Service",
                "Admission, RBAC, or API errors prevented EndpointSlice creation or update",
                "Service discovery objects drifted and Endpoints were populated without corresponding EndpointSlices",
            ],
            "suggested_checks": [
                f"kubectl get endpointslice -l kubernetes.io/service-name={service_name}",
                f"kubectl describe service {service_name}",
                f"kubectl get endpoints {service_name}",
                "Inspect kube-controller-manager and EndpointSlice controller health",
            ],
        }
