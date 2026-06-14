from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class IngressClassMissingRule(FailureRule):
    """
    Detects an Ingress or Gateway API route that cannot be admitted because its
    referenced IngressClass / GatewayClass does not exist.

    Real-world behavior:
    - An Ingress specifies spec.ingressClassName referencing a non-existent
      IngressClass.
    - A Gateway references a non-existent GatewayClass.
    - Controllers emit events such as:
          "IngressClass not found"
          "invalid ingress class"
          "GatewayClass does not exist"
          "waiting for gatewayclass"
    - The workload remains unreachable even though Pods and Services are healthy.
    - No controller claims ownership of the object.

    Exclusions:
    - Existing IngressClass with unhealthy controller.
    - Existing GatewayClass with unhealthy controller.
    - DNS failures.
    - Backend Service failures.
    - TLS/certificate issues.
    - NetworkPolicy issues.
    """

    name = "IngressClassMissing"
    category = "Networking"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "ingress",
            "ingressclass",
            "gateway",
            "gatewayclass",
            "httproute",
            "grpcroute",
            "tlsroute",
            "tcproute",
            "udproute",
            "referencegrant",
            "service",
        ],
    }

    blocks = [
        "IngressControllerUnavailable",
        "GatewayControllerUnavailable",
        "ServiceSelectorMismatch",
        "CoreDNSUnavailable",
    ]

    WINDOW_MINUTES = 30

    INGRESS_CLASS_FAILURE_MARKERS = (
        "ingressclass",
        "ingress class",
        "invalid ingress class",
        "ingress class not found",
        "ingressclass not found",
        "no ingress class",
        "unknown ingress class",
        "referenced ingressclass",
    )

    GATEWAY_CLASS_FAILURE_MARKERS = (
        "gatewayclass",
        "gateway class",
        "gatewayclass not found",
        "gateway class not found",
        "unknown gatewayclass",
        "waiting for gatewayclass",
        "referenced gatewayclass",
    )

    NEGATIVE_STATUS_MARKERS = (
        "accepted=false",
        "resolvedrefs=false",
        "invalid",
        "not found",
        "unknown",
        "rejected",
    )

    CONTROLLER_EXCLUSIONS = (
        "failed to sync",
        "connection refused",
        "i/o timeout",
        "context deadline exceeded",
        "webhook",
        "certificate",
        "x509",
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

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

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

    def _services_for_pod(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        services = []

        for service in context.get("objects", {}).get("service", {}).values():
            if isinstance(service, dict) and self._service_selects_pod(service, pod):
                services.append(service)

        return services

    def _related_ingresses(
        self,
        services: list[dict[str, Any],],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        service_names = {self._object_name(svc) for svc in services}

        ingresses = []

        for ingress in context.get("objects", {}).get("ingress", {}).values():
            if not isinstance(ingress, dict):
                continue

            rules = ingress.get("spec", {}).get("rules", []) or []

            for rule in rules:
                http = rule.get("http", {}) or {}

                for path in http.get("paths", []) or []:
                    backend = path.get("backend", {}) or {}
                    service = backend.get("service", {}) or {}

                    if service.get("name") in service_names:
                        ingresses.append(ingress)
                        break

        return ingresses

    def _related_gateways(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [
            obj
            for obj in context.get("objects", {}).get("gateway", {}).values()
            if isinstance(obj, dict)
        ]

    def _ingressclass_exists(
        self,
        class_name: str,
        context: dict[str, Any],
    ) -> bool:
        return class_name in context.get(
            "objects",
            {},
        ).get("ingressclass", {})

    def _gatewayclass_exists(
        self,
        class_name: str,
        context: dict[str, Any],
    ) -> bool:
        return class_name in context.get(
            "objects",
            {},
        ).get("gatewayclass", {})

    def _ingress_missing_class(
        self,
        ingress: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        class_name = ingress.get("spec", {}).get("ingressClassName")

        if not class_name:
            return False, None

        if self._ingressclass_exists(class_name, context):
            return False, None

        return (
            True,
            f"Ingress references missing IngressClass '{class_name}'",
        )

    def _gateway_missing_class(
        self,
        gateway: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[bool, str | None]:
        class_name = gateway.get("spec", {}).get("gatewayClassName")

        if not class_name:
            return False, None

        if self._gatewayclass_exists(class_name, context):
            return False, None

        return (
            True,
            f"Gateway references missing GatewayClass '{class_name}'",
        )

    def _class_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        matches = []

        for event in self._ordered_recent_events(timeline):
            text = (f"{self._reason(event)} {self._message(event)}").lower()

            if any(marker in text for marker in self.CONTROLLER_EXCLUSIONS):
                continue

            ingress_hit = any(
                marker in text for marker in self.INGRESS_CLASS_FAILURE_MARKERS
            )

            gateway_hit = any(
                marker in text for marker in self.GATEWAY_CLASS_FAILURE_MARKERS
            )

            if ingress_hit or gateway_hit:
                matches.append(event)

        return matches

    def _gateway_negative_conditions(
        self,
        gateway: dict[str, Any],
    ) -> list[str]:
        evidence = []

        for condition in gateway.get("status", {}).get("conditions", []) or []:
            if condition.get("status") != "False":
                continue

            evidence.append(
                f"{condition.get('type')}={condition.get('status')} "
                f"reason={condition.get('reason')}"
            )

        return evidence

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        services = self._services_for_pod(
            pod,
            context,
        )

        if not services:
            return None

        evidence = []
        object_evidence = {}

        ingresses = self._related_ingresses(
            services,
            context,
        )

        for ingress in ingresses:
            missing, msg = self._ingress_missing_class(
                ingress,
                context,
            )

            if missing:
                name = self._object_name(ingress)

                evidence.append(msg)

                object_evidence[f"ingress:{name}"] = [msg]

        for gateway in self._related_gateways(context):
            missing, msg = self._gateway_missing_class(
                gateway,
                context,
            )

            if missing:
                name = self._object_name(gateway)

                evidence.append(msg)

                object_evidence[f"gateway:{name}"] = [msg]

                conditions = self._gateway_negative_conditions(gateway)

                if conditions:
                    object_evidence[f"gateway:{name}"].extend(conditions)

        events = self._class_failure_events(timeline)

        if not evidence and not events:
            return None

        return {
            "evidence": evidence,
            "events": events,
            "object_evidence": object_evidence,
        }

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
            raise ValueError("IngressClassMissing requires Timeline context")

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("IngressClassMissing explain() called without match")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ROUTE_REQUIRES_CLASS",
                    message=(
                        "Ingress or Gateway requires a corresponding "
                        "class resource before a controller can manage it"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="CLASS_RESOURCE_MISSING",
                    message=(
                        "Referenced IngressClass or GatewayClass " "does not exist"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ROUTE_NOT_ADMITTED",
                    message=(
                        "No controller can successfully admit or " "program the route"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = list(candidate["evidence"])

        if candidate["events"]:
            representative = self._message(candidate["events"][-1])

            evidence.append(f"Representative controller event: {representative}")

            evidence.append(
                f"Observed {sum(self._occurrences(e) for e in candidate['events'])} class-resolution failure occurrence(s)"
            )

        confidence = 0.95

        if candidate["events"] and candidate["object_evidence"]:
            confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": (
                "Ingress or Gateway references a missing " "IngressClass/GatewayClass"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(value))
                for key, value in candidate["object_evidence"].items()
            },
            "likely_causes": [
                "IngressClass was deleted after the Ingress was created",
                "GatewayClass was deleted after Gateway creation",
                "A typo exists in ingressClassName",
                "A typo exists in gatewayClassName",
                "Controller installation is incomplete and never created the class resource",
                "A GitOps or IaC deployment applied routes before classes were created",
            ],
            "suggested_checks": [
                "kubectl get ingressclass",
                "kubectl get gatewayclass",
                "kubectl describe ingress <name>",
                "kubectl describe gateway <name>",
                "kubectl get events --sort-by=.lastTimestamp",
                "Verify spec.ingressClassName matches an existing IngressClass",
                "Verify spec.gatewayClassName matches an existing GatewayClass",
            ],
        }
