from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ServicePortMismatchRule(FailureRule):
    """
    Detects workloads that try to reach a Kubernetes Service on a port that the
    Service does not actually publish.

    Real-world behavior:
    - clients must connect to Service.spec.ports[*].port, not the backend
      targetPort or containerPort
    - a common failure is hardcoding the backend application's port
      (for example 8443) while the Service only exposes a front-door port
      (for example 443)
    - in production this often shows up as repeated connection failures against
      an existing Service name even though the Service has ready endpoints
    """

    name = "ServicePortMismatch"
    category = "Networking"
    priority = 44
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["service"],
    }

    optional_objects = ["endpoints", "endpointslice"]
    blocks = ["CrashLoopBackOff"]

    WINDOW_MINUTES = 20
    FAILURE_MARKERS = (
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "timed out",
        "no route to host",
        "connection reset",
    )

    HOST_PORT_RE = re.compile(
        r"(?:(?:https?|tcp)://)?(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+){0,4})(?::(?P<port>\d{1,5}))",
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

    def _extract_refs_from_text(
        self,
        text: str,
        aliases: dict[str, str],
    ) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        lowered = str(text or "").lower()
        for match in self.HOST_PORT_RE.finditer(lowered):
            host = match.group("host")
            port_text = match.group("port")
            if host not in aliases or not port_text:
                continue
            try:
                port = int(port_text)
            except Exception:
                continue
            refs.append(
                {
                    "service_name": aliases[host],
                    "host": host,
                    "port": port,
                    "text": text,
                }
            )
        return refs

    def _configured_refs(
        self,
        pod: dict[str, Any],
        aliases: dict[str, str],
    ) -> dict[tuple[str, int], list[str]]:
        refs: dict[tuple[str, int], list[str]] = {}

        for container in pod.get("spec", {}).get("containers", []) or []:
            container_name = str(container.get("name", "")).strip() or "<unknown>"

            for env in container.get("env", []) or []:
                value = env.get("value")
                if not isinstance(value, str) or ":" not in value:
                    continue
                for ref in self._extract_refs_from_text(value, aliases):
                    refs.setdefault((ref["service_name"], ref["port"]), []).append(
                        f"env {container_name}:{env.get('name', '<env>')}={value}"
                    )

            for field_name in ("command", "args"):
                for item in container.get(field_name, []) or []:
                    if not isinstance(item, str) or ":" not in item:
                        continue
                    for ref in self._extract_refs_from_text(item, aliases):
                        refs.setdefault((ref["service_name"], ref["port"]), []).append(
                            f"{field_name} {container_name}:{item}"
                        )

        return refs

    def _is_network_failure_message(self, message: str) -> bool:
        lowered = str(message or "").lower()
        return any(marker in lowered for marker in self.FAILURE_MARKERS)

    def _event_refs(
        self,
        events: list[dict[str, Any]],
        aliases: dict[str, str],
    ) -> dict[tuple[str, int], dict[str, Any]]:
        refs: dict[tuple[str, int], dict[str, Any]] = {}

        for event in events:
            message = str(event.get("message", ""))
            if not self._is_network_failure_message(message):
                continue

            for ref in self._extract_refs_from_text(message, aliases):
                key = (ref["service_name"], ref["port"])
                bucket = refs.setdefault(
                    key,
                    {
                        "occurrences": 0,
                        "messages": [],
                    },
                )
                bucket["occurrences"] += self._occurrences(event)
                bucket["messages"].append(message)

        return refs

    def _service_ports(self, service: dict[str, Any]) -> tuple[list[int], list[int]]:
        exposed: list[int] = []
        targets: list[int] = []

        for port_spec in service.get("spec", {}).get("ports", []) or []:
            port = port_spec.get("port")
            if isinstance(port, int):
                exposed.append(port)

            target_port = port_spec.get("targetPort")
            if isinstance(target_port, int):
                targets.append(target_port)

        return sorted(set(exposed)), sorted(set(targets))

    def _service_ready_endpoints_state(
        self,
        objects: dict[str, Any],
        service_name: str,
    ) -> bool | None:
        endpoints = objects.get("endpoints", {})
        endpoint_slices = objects.get("endpointslice", {})

        if service_name in endpoints:
            subsets = endpoints[service_name].get("subsets", []) or []
            if not subsets:
                return False
            for subset in subsets:
                if subset.get("addresses"):
                    return True
            return False

        saw_slice = False
        for slice_obj in endpoint_slices.values():
            labels = slice_obj.get("metadata", {}).get("labels", {})
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            saw_slice = True
            for endpoint in slice_obj.get("endpoints", []) or []:
                if endpoint.get("conditions", {}).get("ready") is True:
                    return True
        if saw_slice:
            return False
        return None

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        objects = context.get("objects", {})
        services = objects.get("service", {})
        if not services:
            return None

        namespace = str(pod.get("metadata", {}).get("namespace", "default")).lower()
        aliases = self._service_aliases(services, namespace)
        recent_events = self._ordered_recent_events(timeline)
        if not recent_events:
            return None

        config_refs = self._configured_refs(pod, aliases)
        event_refs = self._event_refs(recent_events, aliases)
        if not event_refs:
            return None

        best: dict[str, Any] | None = None

        for (service_name, expected_port), event_data in event_refs.items():
            service = services.get(service_name, {})
            spec = service.get("spec", {})
            if spec.get("type") == "ExternalName":
                continue

            exposed_ports, target_ports = self._service_ports(service)
            if not exposed_ports:
                continue
            if expected_port in exposed_ports:
                continue

            endpoints_ready = self._service_ready_endpoints_state(objects, service_name)
            if endpoints_ready is False:
                continue

            config_sources = config_refs.get((service_name, expected_port), [])
            candidate = {
                "service_name": service_name,
                "expected_port": expected_port,
                "exposed_ports": exposed_ports,
                "target_ports": target_ports,
                "endpoints_ready": endpoints_ready,
                "occurrences": int(event_data["occurrences"]),
                "dominant_message": max(
                    set(event_data["messages"]),
                    key=lambda message: sum(
                        self._occurrences(event)
                        for event in recent_events
                        if str(event.get("message", "")) == message
                    ),
                ),
                "config_sources": list(dict.fromkeys(config_sources)),
                "expected_matches_target_port": expected_port in target_ports,
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["occurrences"],
                1 if best["expected_matches_target_port"] else 0,
                len(best["config_sources"]),
                1 if best["endpoints_ready"] is True else 0,
            )
            candidate_key = (
                candidate["occurrences"],
                1 if candidate["expected_matches_target_port"] else 0,
                len(candidate["config_sources"]),
                1 if candidate["endpoints_ready"] is True else 0,
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
            raise ValueError("ServicePortMismatch requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("ServicePortMismatch explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        service_name = candidate["service_name"]
        expected_port = candidate["expected_port"]
        exposed_ports = candidate["exposed_ports"]
        target_ports = candidate["target_ports"]
        exposed_port_text = ", ".join(str(port) for port in exposed_ports)

        confidence = 0.92
        if candidate["config_sources"]:
            confidence += 0.02
        if candidate["endpoints_ready"] is True:
            confidence += 0.01
        if candidate["expected_matches_target_port"]:
            confidence += 0.01

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_REFERENCE_CONFIGURED",
                    message=(
                        f"Workload is attempting to reach Service '{service_name}' on port "
                        f"{expected_port}"
                    ),
                    role="service_context",
                ),
                Cause(
                    code="SERVICE_PORT_MISMATCH",
                    message=(
                        f"Service '{service_name}' exposes port(s) {exposed_port_text}, "
                        f"but clients are using port {expected_port}"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SERVICE_CONNECTION_FAILURE",
                    message=(
                        "The Service name resolves, but traffic is sent to a port that the "
                        "Service does not publish"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Recent workload failures reference Service '{service_name}' on port "
                f"{expected_port}, but the Service publishes port(s) {exposed_port_text}"
            ),
            (
                f"Port mismatch symptoms were observed {candidate['occurrences']} time(s) "
                f"within the last {self.WINDOW_MINUTES} minutes"
            ),
        ]
        if candidate["endpoints_ready"] is True:
            evidence.append(
                f"Service '{service_name}' has ready endpoints, so the failure is not explained by empty backends"
            )
        if candidate["expected_matches_target_port"]:
            evidence.append(
                f"Requested port {expected_port} matches Service targetPort, suggesting clients are using the backend port instead of the Service port"
            )
        if candidate["config_sources"]:
            evidence.append(
                "Workload configuration explicitly references the mismatched Service port"
            )

        object_evidence = {
            f"service:{service_name}": [
                f"Service exposes ports {exposed_port_text}",
            ],
            f"pod:{pod_name}": [
                candidate["dominant_message"],
            ],
        }
        if target_ports:
            object_evidence[f"service:{service_name}"].append(
                "Service targetPorts " + ", ".join(str(port) for port in target_ports)
            )
        if candidate["endpoints_ready"] is True:
            object_evidence[f"service:{service_name}"].append(
                "Ready endpoints exist for the Service"
            )
        for source in candidate["config_sources"][:2]:
            object_evidence[f"pod:{pod_name}"].append(source)

        return {
            "root_cause": (
                f"Application is calling Service '{service_name}' on port "
                f"{expected_port}, but the Service only exposes port {exposed_port_text}"
            ),
            "confidence": min(0.97, confidence),
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The application is hardcoded to use the backend targetPort or containerPort instead of Service.spec.ports[*].port",
                "A Helm value or application setting still points to an old Service port after the Service was changed",
                "Client-side dependency configuration drifted from the Kubernetes Service definition",
            ],
            "suggested_checks": [
                f"kubectl describe service {service_name}",
                f"kubectl get endpoints {service_name}",
                f"kubectl describe pod {pod_name}",
                "Compare the application's configured dependency URL/port with Service.spec.ports[*].port rather than targetPort",
            ],
        }
