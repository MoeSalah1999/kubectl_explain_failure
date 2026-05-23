from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class LoadBalancerProvisioningFailedRule(FailureRule):
    """
    Detects cloud-provider LoadBalancer Service provisioning failures.

    Real-world behavior:
    - managed clusters rely on a cloud-controller-manager or provider-specific
      controller to turn a Kubernetes Service of type LoadBalancer into a cloud
      load balancer
    - failures commonly leave the Service with an empty
      status.loadBalancer.ingress list while workloads keep running internally
    - user-facing traffic remains unavailable until cloud subnet, IAM, quota,
      security-group, or provider API failures are resolved
    """

    name = "LoadBalancerProvisioningFailed"
    category = "Networking"
    severity = "High"
    priority = 73
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["service"],
        "optional_objects": ["endpoints", "endpointslice"],
    }

    blocks = [
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
        "ServicePortMismatch",
    ]

    WINDOW_MINUTES = 30
    FAILURE_REASONS = {
        "syncloadbalancerfailed",
        "creatingloadbalancerfailed",
        "ensuringloadbalancerfailed",
        "updateloadbalancerfailed",
        "deletingloadbalancerfailed",
        "loadbalancerupdatefailed",
        "failedbuildmodelloadbalancer",
        "faileddeploymodelloadbalancer",
    }
    SUCCESS_REASONS = {
        "ensuredloadbalancer",
        "createdloadbalancer",
        "updatedloadbalancer",
        "syncloadbalancersucceeded",
    }
    CONTROLLER_MARKERS = (
        "service-controller",
        "cloud-controller-manager",
        "aws-load-balancer-controller",
        "azure-cloud-controller-manager",
        "gce-controller-manager",
        "digitalocean-cloud-controller-manager",
        "openstack-cloud-controller-manager",
        "load balancer controller",
    )
    LOAD_BALANCER_MARKERS = (
        "load balancer",
        "loadbalancer",
        "lb ",
        "elasticloadbalancing",
        "elbv2",
        "network load balancer",
        "application load balancer",
        "forwarding rule",
    )
    CLOUD_FAILURE_MARKERS = (
        "failed to ensure load balancer",
        "failed to create load balancer",
        "failed to update load balancer",
        "error syncing load balancer",
        "error creating load balancer",
        "error ensuring load balancer",
        "could not find any suitable subnets",
        "unable to resolve at least one subnet",
        "subnet not found",
        "invalidsubnet",
        "invalid subnet",
        "insufficientfreeaddressesinsubnet",
        "insufficient free addresses",
        "loadbalancerlimitexceeded",
        "load balancer limit exceeded",
        "quota",
        "limitexceeded",
        "throttling",
        "requestlimitexceeded",
        "accessdenied",
        "access denied",
        "unauthorizedoperation",
        "permission",
        "iam",
        "security group",
        "securitygroup",
        "unsupportedavailabilityzone",
        "unsupported availability zone",
        "failed calling cloud provider",
        "cloud provider",
        "provider api",
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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "")
        return str(source or "")

    def _normalized(self, value: str) -> str:
        return " ".join(value.lower().replace("_", " ").replace("-", " ").split())

    def _compact(self, value: str) -> str:
        return self._normalized(value).replace(" ", "")

    def _has_any(self, text: str, markers: tuple[str, ...]) -> bool:
        normalized = self._normalized(text)
        compact = normalized.replace(" ", "")
        return any(marker in normalized or marker in compact for marker in markers)

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
        labels = pod.get("metadata", {}).get("labels", {}) or {}
        return {str(key): str(value) for key, value in labels.items()}

    def _selector_matches_pod(
        self, service: dict[str, Any], pod: dict[str, Any]
    ) -> bool:
        selector = service.get("spec", {}).get("selector", {}) or {}
        if not selector:
            return False
        labels = self._pod_labels(pod)
        return all(
            labels.get(str(key)) == str(value) for key, value in selector.items()
        )

    def _load_balancer_ingress_assigned(self, service: dict[str, Any]) -> bool:
        ingress = service.get("status", {}).get("loadBalancer", {}).get("ingress", [])
        return isinstance(ingress, list) and bool(ingress)

    def _candidate_services(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        services = context.get("objects", {}).get("service", {}) or {}
        pod_namespace = pod.get("metadata", {}).get("namespace", "default")
        candidates: list[dict[str, Any]] = []

        for service in services.values():
            if not isinstance(service, dict):
                continue
            if service.get("spec", {}).get("type") != "LoadBalancer":
                continue
            if self._object_namespace(service) != pod_namespace:
                continue
            if not self._selector_matches_pod(service, pod):
                continue
            if self._load_balancer_ingress_assigned(service):
                continue
            candidates.append(service)

        return candidates

    def _event_targets_service(
        self,
        event: dict[str, Any],
        service: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return False

        kind = str(involved.get("kind") or "").lower()
        if kind and kind != "service":
            return False

        service_name = self._object_name(service)
        service_namespace = self._object_namespace(service)
        if involved.get("name") and involved.get("name") != service_name:
            return False
        if involved.get("namespace") and involved.get("namespace") != service_namespace:
            return False
        return True

    def _is_lb_failure_event(
        self,
        event: dict[str, Any],
        service: dict[str, Any],
    ) -> bool:
        if not self._event_targets_service(event, service):
            return False

        reason = self._compact(self._reason(event))
        message = self._message(event)
        source = self._source_component(event)
        event_text = f"{source} {self._reason(event)} {message}"

        reason_is_failure = reason in self.FAILURE_REASONS
        has_lb = self._has_any(event_text, self.LOAD_BALANCER_MARKERS)
        has_cloud_failure = self._has_any(event_text, self.CLOUD_FAILURE_MARKERS)
        has_controller = self._has_any(event_text, self.CONTROLLER_MARKERS)

        return (reason_is_failure or has_controller) and has_lb and has_cloud_failure

    def _is_lb_success_event(
        self,
        event: dict[str, Any],
        service: dict[str, Any],
    ) -> bool:
        if not self._event_targets_service(event, service):
            return False
        return self._compact(self._reason(event)) in self.SUCCESS_REASONS

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

    def _service_failures(
        self,
        service: dict[str, Any],
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        return [
            event
            for event in self._ordered_recent_events(timeline)
            if self._is_lb_failure_event(event, service)
        ]

    def _failure_duration_seconds(
        self,
        service: dict[str, Any],
        timeline: Timeline,
    ) -> float:
        def is_failure_for_service(event: dict[str, Any]) -> bool:
            return self._is_lb_failure_event(event, service)

        return timeline.duration_between(is_failure_for_service)

    def _success_after(
        self,
        service: dict[str, Any],
        timeline: Timeline,
        latest_failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_lb_success_event(event, service):
                continue
            event_at = self._event_time(event)
            if (
                latest_failure_at is None
                or event_at is None
                or event_at >= latest_failure_at
            ):
                return True
        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        best: dict[str, Any] | None = None
        for service in self._candidate_services(pod, context):
            failures = self._service_failures(service, timeline)
            if not failures:
                continue

            latest_failure_at = self._event_time(failures[-1])
            if self._success_after(service, timeline, latest_failure_at):
                continue

            occurrences = sum(self._occurrences(event) for event in failures)
            duration_seconds = self._failure_duration_seconds(service, timeline)
            candidate = {
                "service": service,
                "failures": failures,
                "occurrences": occurrences,
                "duration_seconds": duration_seconds,
            }
            if best is None:
                best = candidate
                continue
            best_key = (best["occurrences"], best["duration_seconds"])
            candidate_key = (occurrences, duration_seconds)
            if candidate_key > best_key:
                best = candidate
        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("LoadBalancerProvisioningFailed requires Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "LoadBalancerProvisioningFailed explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        service = candidate["service"]
        service_name = self._object_name(service)
        failures = candidate["failures"]
        latest = failures[-1]
        latest_message = self._message(latest)
        latest_reason = self._reason(latest) or "<unknown>"
        occurrences = candidate["occurrences"]
        duration_seconds = candidate["duration_seconds"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_REQUIRES_CLOUD_LOAD_BALANCER",
                    message=f"Service '{service_name}' exposes the workload through a cloud LoadBalancer",
                    role="service_context",
                ),
                Cause(
                    code="LOAD_BALANCER_PROVISIONING_FAILED",
                    message="The cloud provider could not provision or reconcile the external load balancer",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="EXTERNAL_TRAFFIC_BLOCKED",
                    message="External clients cannot reach the workload until the LoadBalancer is provisioned",
                    role="service_symptom",
                ),
            ]
        )

        evidence = [
            f"Service {namespace}/{service_name} is type LoadBalancer and selects pod {pod_name}",
            "Service status.loadBalancer.ingress is empty, so no external address has been assigned",
            f"Latest LoadBalancer provisioning failure reason: {latest_reason}",
            f"Latest LoadBalancer provisioning failure message: {latest_message}",
            f"Observed {occurrences} cloud LoadBalancer provisioning failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            "No successful LoadBalancer provisioning event was observed after the latest failure",
        ]
        if duration_seconds:
            evidence.append(
                f"LoadBalancer provisioning failures persisted for {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "Cloud LoadBalancer provisioning failed for Service",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"service:{service_name}": [
                    "LoadBalancer Service has no assigned external ingress",
                    latest_message,
                ],
                f"pod:{pod_name}": [
                    f"Pod is selected by Service '{service_name}', whose external LoadBalancer is not provisioned"
                ],
                "timeline:loadbalancer": [
                    latest_message,
                ],
            },
            "likely_causes": [
                "Cloud subnet tags or route configuration do not allow load balancer placement",
                "Cloud quota or load balancer limits prevent creating another load balancer",
                "The cloud-controller-manager or load balancer controller lacks required IAM permissions",
                "Security group, firewall, or availability-zone constraints prevent provider reconciliation",
            ],
            "suggested_checks": [
                f"kubectl describe service {service_name} -n {namespace}",
                "Check cloud-controller-manager or cloud load balancer controller logs for reconciliation errors",
                "Verify subnet tags, availability zones, security groups, and cloud load balancer quotas",
                "Confirm controller IAM permissions for creating and tagging load balancers, listeners, target groups, and security groups",
                f"kubectl get endpoints {service_name} -n {namespace}",
            ],
        }
