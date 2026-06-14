from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class IngressBackendServiceInvalidRule(FailureRule):
    """
    Detects Ingress/Gateway API routing failures caused by an invalid backend
    Service reference.

    Real-world behavior:
    - Ingress backend Service does not exist.
    - Gateway API HTTPRoute/TLSRoute backendRef references a missing Service.
    - Backend Service exists but has no usable ports matching the route.
    - Controller emits reconciliation errors for missing or invalid Services.
    - Endpoint availability is intentionally NOT diagnosed here
      (handled by separate backend/endpoints rules).

    Exclusions:
    - Existing Service with temporarily empty Endpoints.
    - Pod readiness failures behind an existing Service.
    - TLS/certificate failures.
    - NetworkPolicy/connectivity failures.
    """

    name = "IngressBackendServiceInvalid"
    category = "Networking"
    severity = "High"
    priority = 82
    deterministic = True

    phases = ["Pending", "Running", "Succeeded", "Failed"]

    requires = {
        "pod": False,
        "context": ["timeline"],
        "optional_objects": [
            "ingress",
            "gateway",
            "httproute",
            "grpcroute",
            "tlsroute",
            "tcproute",
            "service",
        ],
    }

    WINDOW_MINUTES = 30

    CONTROLLER_HINTS = (
        "ingress",
        "gateway",
        "gateway-api",
        "nginx",
        "traefik",
        "contour",
        "envoy",
        "haproxy",
    )

    SERVICE_ERROR_MARKERS = (
        "service",
        "backend",
        "backendref",
        "backend ref",
        "service not found",
        "service does not exist",
        "could not find service",
        "unable to find service",
        "no such service",
        "failed to get service",
        "failed to fetch service",
        "backend service",
        "invalid backend",
        "backend not found",
        "resource not found",
    )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _event_text(self, event: dict[str, Any]) -> str:
        return (
            f"{event.get('type','')} "
            f"{self._reason(event)} "
            f"{self._message(event)}"
        ).lower()

    def _event_matches(self, event: dict[str, Any]) -> bool:
        text = self._event_text(event)

        if not any(h in text for h in self.CONTROLLER_HINTS):
            return False

        return any(marker in text for marker in self.SERVICE_ERROR_MARKERS)

    def _service_exists(
        self,
        context: dict[str, Any],
        namespace: str,
        name: str,
    ) -> dict[str, Any] | None:
        services = context.get("objects", {}).get("service", {})

        for svc in services.values():
            if not isinstance(svc, dict):
                continue

            md = svc.get("metadata", {})

            if md.get("namespace", "default") == namespace and md.get("name") == name:
                return svc

        return None

    def _service_has_port(
        self,
        svc: dict[str, Any],
        port: Any,
    ) -> bool:
        """
        Kubernetes permits backend ports by numeric value or by name.
        If route omitted port entirely, existence of Service is sufficient.
        """
        if port is None:
            return True

        ports = svc.get("spec", {}).get("ports", []) or []

        for p in ports:
            if not isinstance(p, dict):
                continue

            if p.get("port") == port:
                return True

            if str(p.get("port")) == str(port):
                return True

            if p.get("name") == port:
                return True

            if str(p.get("name")) == str(port):
                return True

        return False

    # ------------------------------------------------------------------ #
    # Backend extraction
    # ------------------------------------------------------------------ #

    def _collect_ingress_backends(
        self,
        context: dict[str, Any],
    ) -> list[tuple[str, str, Any, str]]:
        refs = []

        for ing in context.get("objects", {}).get("ingress", {}).values():
            if not isinstance(ing, dict):
                continue

            md = ing.get("metadata", {})
            namespace = md.get("namespace", "default")
            owner = f"ingress:{md.get('name','<unknown>')}"

            spec = ing.get("spec", {}) or {}

            default_backend = spec.get("defaultBackend")
            if isinstance(default_backend, dict):
                svc = default_backend.get("service") or {}
                if svc.get("name"):
                    refs.append(
                        (
                            namespace,
                            svc["name"],
                            (svc.get("port") or {}).get("number")
                            or (svc.get("port") or {}).get("name"),
                            owner,
                        )
                    )

            for rule in spec.get("rules", []) or []:
                http = rule.get("http") or {}

                for path in http.get("paths", []) or []:
                    backend = path.get("backend") or {}
                    service = backend.get("service") or {}

                    if not service.get("name"):
                        continue

                    refs.append(
                        (
                            namespace,
                            service["name"],
                            (service.get("port") or {}).get("number")
                            or (service.get("port") or {}).get("name"),
                            owner,
                        )
                    )

        return refs

    def _collect_gateway_backends(
        self,
        context: dict[str, Any],
    ) -> list[tuple[str, str, Any, str]]:
        refs = []

        route_kinds = (
            "httproute",
            "grpcroute",
            "tlsroute",
            "tcproute",
        )

        for kind in route_kinds:
            for route in context.get("objects", {}).get(kind, {}).values():
                if not isinstance(route, dict):
                    continue

                md = route.get("metadata", {})
                namespace = md.get("namespace", "default")
                owner = f"{kind}:{md.get('name','<unknown>')}"

                for rule in route.get("spec", {}).get("rules", []) or []:
                    for backend in rule.get("backendRefs", []) or []:
                        backend_kind = backend.get("kind", "Service")

                        if backend_kind != "Service":
                            continue

                        name = backend.get("name")
                        if not name:
                            continue

                        refs.append(
                            (
                                namespace,
                                name,
                                backend.get("port"),
                                owner,
                            )
                        )

        return refs

    # ------------------------------------------------------------------ #
    # Candidate
    # ------------------------------------------------------------------ #

    def _candidate(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        refs = self._collect_ingress_backends(context) + self._collect_gateway_backends(
            context
        )

        if not refs:
            return None

        missing_services: list[tuple[str, str, str]] = []
        invalid_ports: list[tuple[str, str, Any, str]] = []

        object_evidence: dict[str, list[str]] = {}

        for namespace, svc_name, port, owner in refs:
            svc = self._service_exists(
                context,
                namespace,
                svc_name,
            )

            if svc is None:
                missing_services.append(
                    (
                        namespace,
                        svc_name,
                        owner,
                    )
                )

                object_evidence.setdefault(
                    f"service:{namespace}/{svc_name}",
                    [],
                ).append("Referenced backend Service does not exist")
                continue

            if not self._service_has_port(svc, port):
                invalid_ports.append(
                    (
                        namespace,
                        svc_name,
                        port,
                        owner,
                    )
                )

                object_evidence.setdefault(
                    f"service:{namespace}/{svc_name}",
                    [],
                ).append(f"Referenced backend port '{port}' does not exist on Service")

        matching_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._event_matches(e)
        ]

        if not missing_services and not invalid_ports and not matching_events:
            return None

        return {
            "missing_services": missing_services,
            "invalid_ports": invalid_ports,
            "events": matching_events,
            "object_evidence": object_evidence,
        }

    # ------------------------------------------------------------------ #
    # Rule API
    # ------------------------------------------------------------------ #

    def matches(self, pod, events, context) -> bool:
        return self._candidate(context) is not None

    def explain(self, pod, events, context):
        candidate = self._candidate(context)

        if candidate is None:
            raise ValueError(
                "IngressBackendServiceInvalid explain() called without match"
            )

        evidence: list[str] = []

        for namespace, svc, owner in candidate["missing_services"]:
            evidence.append(f"{owner} references missing Service " f"{namespace}/{svc}")

        for namespace, svc, port, owner in candidate["invalid_ports"]:
            evidence.append(
                f"{owner} references nonexistent port "
                f"{port} on Service {namespace}/{svc}"
            )

        for event in candidate["events"][:3]:
            msg = self._message(event)
            if msg:
                evidence.append(msg)

        chain = CausalChain(
            causes=[
                Cause(
                    code="INGRESS_ROUTE_REFERENCES_SERVICE",
                    message="Ingress or Gateway route references a backend Service",
                    role="runtime_context",
                ),
                Cause(
                    code="BACKEND_SERVICE_REFERENCE_INVALID",
                    message="Referenced backend Service or backend port is invalid",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="ROUTE_CANNOT_FORWARD_TO_BACKEND",
                    message="Ingress/Gateway controller cannot configure backend forwarding",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = dict(candidate["object_evidence"])

        confidence = 0.90

        if candidate["missing_services"] or candidate["invalid_ports"]:
            confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": ("Ingress/Gateway backend Service reference is invalid"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": object_evidence,
            "likely_causes": [
                "Referenced Service does not exist",
                "Ingress references an incorrect Service name",
                "Gateway API backendRef points to a nonexistent Service",
                "Referenced Service port does not exist",
                "Service was deleted after route creation",
                "Manifest was deployed in the wrong namespace",
            ],
            "suggested_checks": [
                "kubectl get ingress -A -o yaml",
                "kubectl get httproute -A -o yaml",
                "kubectl get gateway -A -o yaml",
                "kubectl get svc -A",
                "kubectl describe ingress <name>",
                "kubectl describe httproute <name>",
                "kubectl describe gateway <name>",
                "kubectl describe svc <service-name>",
            ],
        }
