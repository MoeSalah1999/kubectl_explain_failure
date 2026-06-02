from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class APIServiceUnavailableRule(FailureRule):
    """
    Detects failures involving Kubernetes aggregated API services
    (APIService objects registered through kube-aggregator).

    Real-world interpretation:
    - metrics.k8s.io unavailable
    - custom metrics APIs failing
    - external metrics providers unreachable
    - extension API servers unhealthy
    - aggregated admission-style dependencies degraded
    - kube-aggregator cannot reach backing services

    These failures commonly break:
    - kubectl top
    - HPA scaling
    - CRD-backed platform extensions
    - operators depending on aggregated APIs
    - admission and policy ecosystems

    This is fundamentally an API machinery / aggregation-layer failure.
    """

    name = "APIServiceUnavailable"
    category = "API Machinery"
    priority = 94
    deterministic = True

    blocks = [
        "MetricsServerUnavailable",
        "HorizontalPodAutoscalerFailed",
        "AdmissionWebhookDenied",
        "CustomMetricsUnavailable",
        "ExternalMetricsUnavailable",
    ]

    requires = {
        "objects": ["apiservice"],
    }

    supported_phases = {
        "Pending",
        "Running",
        "Succeeded",
        "Failed",
        "Unknown",
    }

    UNAVAILABLE_REASONS = {
        "FailedDiscoveryCheck",
        "MissingEndpoints",
        "ServiceNotFound",
        "ServiceAccessError",
        "EndpointsNotFound",
        "InvalidCertificate",
    }

    UNAVAILABLE_MESSAGE_MARKERS = (
        "failing or missing response",
        "no response from",
        "service unavailable",
        "endpoints not found",
        "no endpoints available",
        "x509:",
        "tls:",
        "context deadline exceeded",
        "connection refused",
        "i/o timeout",
        "503",
    )

    API_RELATED_EVENT_REASONS = {
        "FailedDiscoveryCheck",
        "FailedCallingWebhook",
        "FailedGetResourceMetric",
        "FailedComputeMetricsReplicas",
        "FailedSync",
    }

    def _apiservice_objects(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("apiservice", {})

    def _condition(
        self,
        apiservice: dict[str, Any],
        condition_type: str,
    ) -> dict[str, Any] | None:
        conditions = apiservice.get("status", {}).get("conditions", [])

        for condition in conditions:
            if condition.get("type") == condition_type:
                return condition

        return None

    def _apiservice_unavailable(
        self,
        apiservice: dict[str, Any],
    ) -> bool:
        available = self._condition(
            apiservice,
            "Available",
        )

        if not available:
            return False

        status = str(available.get("status", "")).lower()

        if status == "false":
            return True

        reason = str(available.get("reason", ""))

        return reason in self.UNAVAILABLE_REASONS

    def _apiservice_name(
        self,
        apiservice: dict[str, Any],
    ) -> str:
        return str(apiservice.get("metadata", {}).get("name", "<unknown>"))

    def _service_reference(
        self,
        apiservice: dict[str, Any],
    ) -> str:
        service = apiservice.get("spec", {}).get("service", {})

        namespace = service.get("namespace", "default")
        name = service.get("name", "<unknown>")

        return f"{namespace}/{name}"

    def _condition_message(
        self,
        apiservice: dict[str, Any],
    ) -> str:
        available = self._condition(
            apiservice,
            "Available",
        )

        if not available:
            return ""

        return str(available.get("message", "")).strip()

    def _condition_reason(
        self,
        apiservice: dict[str, Any],
    ) -> str:
        available = self._condition(
            apiservice,
            "Available",
        )

        if not available:
            return ""

        return str(available.get("reason", "")).strip()

    def _event_text(
        self,
        event: dict[str, Any],
    ) -> str:
        reason = str(event.get("reason", ""))
        message = str(event.get("message", ""))

        return f"{reason} {message}".lower()

    def _event_targets_apiservice(
        self,
        event: dict[str, Any],
        apiservice_name: str,
    ) -> bool:
        involved = event.get("involvedObject", {})

        if (
            str(involved.get("kind", "")).lower() == "apiservice"
            and involved.get("name") == apiservice_name
        ):
            return True

        return apiservice_name.lower() in self._event_text(event)

    def _apiservice_failure_event(
        self,
        events,
        apiservice_name: str,
    ) -> dict[str, Any] | None:
        for event in events or []:
            if not self._event_targets_apiservice(
                event,
                apiservice_name,
            ):
                continue

            reason = str(event.get("reason", ""))

            if reason in self.API_RELATED_EVENT_REASONS:
                return event

            text = self._event_text(event)

            if any(marker in text for marker in self.UNAVAILABLE_MESSAGE_MARKERS):
                return event

        return None

    def _correlated_failure(
        self,
        apiservice: dict[str, Any],
        events,
    ) -> dict[str, Any] | None:
        if not self._apiservice_unavailable(apiservice):
            return None

        apiservice_name = self._apiservice_name(apiservice)

        event = self._apiservice_failure_event(
            events,
            apiservice_name,
        )

        if event is not None:
            return {
                "source": "event",
                "event": event,
            }

        return {
            "source": "condition",
            "event": None,
        }

    def matches(self, pod, events, context) -> bool:
        apiservices = self._apiservice_objects(context)

        if not apiservices:
            return False

        for apiservice in apiservices.values():
            if (
                self._correlated_failure(
                    apiservice,
                    events,
                )
                is not None
            ):
                return True

        return False

    def explain(self, pod, events, context):
        apiservices = self._apiservice_objects(context)

        matched = None
        correlation = None

        for apiservice in apiservices.values():
            correlation = self._correlated_failure(
                apiservice,
                events,
            )

            if correlation is not None:
                matched = apiservice
                break

        if matched is None or correlation is None:
            raise ValueError("APIServiceUnavailable explain() called without match")

        apiservice_name = self._apiservice_name(matched)

        service_ref = self._service_reference(matched)

        reason = self._condition_reason(matched)
        message = self._condition_message(matched)

        available = self._condition(
            matched,
            "Available",
        )

        status = "Unknown"

        if available:
            status = str(available.get("status", "Unknown"))

        pod_name = pod.get("metadata", {}).get(
            "name",
            "<unknown>",
        )

        event_message = ""

        if correlation["event"] is not None:
            event_message = str(correlation["event"].get("message", "")).strip()

        chain = CausalChain(
            causes=[
                Cause(
                    code="AGGREGATED_API_UNAVAILABLE",
                    message=("An aggregated APIService is unavailable"),
                    role="aggregation_root",
                ),
                Cause(
                    code="KUBE_AGGREGATOR_FAILURE",
                    message=(
                        "kube-apiserver aggregation layer cannot "
                        "successfully communicate with the backing API service"
                    ),
                    role="api_machinery",
                    blocking=True,
                ),
                Cause(
                    code="API_DEPENDENCY_DEGRADED",
                    message=(
                        "Metrics, custom resources, or extension APIs "
                        "depending on the aggregated service are degraded"
                    ),
                    role="platform_dependency",
                ),
                Cause(
                    code="WORKLOAD_IMPACT",
                    message=(
                        "Controllers or workloads depending on the API "
                        "experience reconciliation or admission failures"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                f"Aggregated APIService {apiservice_name} " "is unavailable"
            ),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"APIService={apiservice_name}",
                f"Available={status}",
                f"Reason={reason}",
                f"Backing service={service_ref}",
                *([message] if message else []),
                *([event_message] if event_message else []),
            ],
            "object_evidence": {
                f"apiservice:{apiservice_name}": [
                    f"Available={status}",
                    f"Reason={reason}",
                    f"Backing service={service_ref}",
                    *([message] if message else []),
                ],
                f"pod:{pod_name}": [
                    "Workload behavior may depend on aggregated APIs",
                    "API aggregation failure can break metrics and admission flows",
                    *([event_message] if event_message else []),
                ],
            },
            "likely_causes": [
                "Metrics server is down or unreachable",
                "Backing Service for the APIService has no healthy endpoints",
                "TLS certificate validation failure between kube-apiserver and extension API",
                "Expired serving certificates",
                "DNS or ClusterIP routing failure",
                "NetworkPolicy blocking kube-apiserver traffic",
                "Aggregated API server crash looping",
                "Extension API deployment rollout failure",
            ],
            "suggested_checks": [
                "kubectl get apiservices",
                (f"kubectl describe apiservice " f"{apiservice_name}"),
                (f"kubectl get svc,endpoints " f"-n {service_ref.split('/')[0]}"),
                ("kubectl get --raw " f"'/apis/{apiservice_name.split('.')[0]}'"),
                ("kubectl logs -n kube-system " "-l component=kube-apiserver"),
                "Inspect APIService condition messages",
                "Verify extension API TLS certificates",
                "Validate endpoint readiness for backing services",
            ],
        }
