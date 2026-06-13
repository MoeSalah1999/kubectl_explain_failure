from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class EndpointSliceTerminatingOnlyRule(FailureRule):
    """
    Detects Services whose EndpointSlices contain only terminating or
    non-ready endpoints.

    Real-world behavior:
    - EndpointSlice objects still exist
    - Service lookup succeeds
    - kube-proxy / clients can discover endpoints
    - every endpoint is either:
        * terminating=true
        * ready=false
        * serving=false
    - requests fail because no backend is actually available

    Common during:
    - rolling updates
    - pod evictions
    - scale-down races
    - StatefulSet replacement
    - endpoint controller propagation delays

    Excludes:
    - Services with at least one ready endpoint
    - Complete Service selector mismatches
    - Missing EndpointSlices
    - CoreDNS failures
    """

    name = "EndpointSliceTerminatingOnly"
    category = "Networking"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["endpointslice"],
        "optional_objects": [
            "service",
            "pod",
        ],
    }

    blocks = [
        "ServiceConnectivityFailure",
        "NoServiceEndpoints",
    ]

    SERVICE_FAILURE_MARKERS = (
        "connection refused",
        "connection reset by peer",
        "upstream connect error",
        "upstream request timeout",
        "503",
        "502",
        "504",
        "no healthy upstream",
        "backend unavailable",
        "service unavailable",
        "context deadline exceeded",
    )

    def _service_name(self, pod: dict[str, Any]) -> str | None:
        labels = pod.get("metadata", {}).get("labels", {}) or {}

        for service in (
            pod.get("metadata", {})
            .get("annotations", {})
            .get("service-name", "")
            .split(",")
        ):
            service = service.strip()
            if service:
                return service

        owner_refs = pod.get("metadata", {}).get("ownerReferences", []) or []
        if owner_refs:
            return None

        return labels.get("app") or labels.get("service")

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _is_service_failure_event(self, event: dict[str, Any]) -> bool:
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        return any(marker in text for marker in self.SERVICE_FAILURE_MARKERS)

    def _slice_matches_service(
        self,
        slice_obj: dict[str, Any],
        service_name: str | None,
        namespace: str,
    ) -> bool:
        if not service_name:
            return False

        metadata = slice_obj.get("metadata", {}) or {}

        if metadata.get("namespace", "default") != namespace:
            return False

        labels = metadata.get("labels", {}) or {}

        return labels.get("kubernetes.io/service-name") == service_name

    def _endpoint_state(
        self,
        endpoint: dict[str, Any],
    ) -> tuple[bool, bool, bool]:
        conditions = endpoint.get("conditions", {}) or {}

        ready = conditions.get("ready")
        serving = conditions.get("serving")
        terminating = conditions.get("terminating")

        return (
            ready is True,
            serving is True,
            terminating is True,
        )

    def _find_terminating_only_service(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        namespace = pod.get("metadata", {}).get(
            "namespace",
            "default",
        )

        service_name = self._service_name(pod)

        endpoint_slices = context.get(
            "objects",
            {},
        ).get(
            "endpointslice",
            {},
        )

        matching_slices = []

        for slice_obj in endpoint_slices.values():
            if not isinstance(slice_obj, dict):
                continue

            if self._slice_matches_service(
                slice_obj,
                service_name,
                namespace,
            ):
                matching_slices.append(slice_obj)

        if not matching_slices:
            return None

        total_endpoints = 0
        ready_endpoints = 0
        terminating_endpoints = 0

        for slice_obj in matching_slices:
            for endpoint in slice_obj.get("endpoints", []) or []:
                total_endpoints += 1

                ready, serving, terminating = self._endpoint_state(endpoint)

                if ready and not terminating:
                    ready_endpoints += 1

                if terminating:
                    terminating_endpoints += 1

                if serving and not terminating:
                    ready_endpoints += 1

        if total_endpoints == 0:
            return None

        if ready_endpoints > 0:
            return None

        if terminating_endpoints == 0:
            return None

        return {
            "service_name": service_name,
            "total_endpoints": total_endpoints,
            "terminating_endpoints": terminating_endpoints,
            "slice_count": len(matching_slices),
        }

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        service_state = self._find_terminating_only_service(
            pod,
            context,
        )

        if not service_state:
            return None

        failure_events = [
            event for event in timeline.events if self._is_service_failure_event(event)
        ]

        return {
            "service": service_state,
            "failure_events": failure_events,
        }

    def matches(self, pod, events, context) -> bool:
        return (
            self._candidate(
                pod,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        candidate = self._candidate(
            pod,
            context,
        )

        if candidate is None:
            raise ValueError(
                "EndpointSliceTerminatingOnly explain() called without match"
            )

        service = candidate["service"]

        namespace = pod.get(
            "metadata",
            {},
        ).get(
            "namespace",
            "default",
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_SELECTED_ENDPOINTS",
                    message="Service resolves to EndpointSlice endpoints",
                    role="runtime_context",
                ),
                Cause(
                    code="ALL_ENDPOINTS_TERMINATING",
                    message="Every endpoint in the EndpointSlices is terminating or unavailable",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="NO_ROUTABLE_BACKENDS",
                    message="Traffic cannot reach a healthy backend pod",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Service {service['service_name']} has "
                f"{service['total_endpoints']} endpoint(s)"
            ),
            (f"All {service['terminating_endpoints']} endpoint(s) " f"are terminating"),
            (
                f"Endpoint information spans "
                f"{service['slice_count']} EndpointSlice object(s)"
            ),
            ("No ready non-terminating endpoint exists " "for the Service"),
        ]

        if candidate["failure_events"]:
            evidence.append(
                f"Representative failure: "
                f"{self._message(candidate['failure_events'][-1])}"
            )

        return {
            "rule": self.name,
            "root_cause": ("Service EndpointSlices contain only terminating endpoints"),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"service:{service['service_name']}": [
                    "All EndpointSlice endpoints are terminating"
                ]
            },
            "likely_causes": [
                "Rolling update terminated all backends before replacements became Ready",
                "Replica count temporarily dropped to zero during deployment",
                "StatefulSet replacement left only terminating pods in EndpointSlices",
                "Pod eviction or drain operation removed all serving backends",
                "EndpointSlice controller has not yet observed replacement Ready pods",
            ],
            "suggested_checks": [
                (
                    f"kubectl get endpointslices -n {namespace} "
                    f"-l kubernetes.io/service-name={service['service_name']} -o yaml"
                ),
                (f"kubectl get pods -n {namespace} " f"-o wide"),
                (
                    f"kubectl describe service {service['service_name']} "
                    f"-n {namespace}"
                ),
                (f"kubectl rollout status deployment " f"-n {namespace}"),
                (
                    "Verify at least one backend pod becomes "
                    "Ready before existing pods terminate"
                ),
            ],
        }
