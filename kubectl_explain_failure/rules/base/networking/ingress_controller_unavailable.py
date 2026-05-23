from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class IngressControllerUnavailableRule(FailureRule):
    """
    Detects application readiness failures caused by an unavailable ingress
    controller dependency.

    Real-world behavior:
    - app readiness checks often validate public callback URLs, OAuth redirect
      hosts, tenant hostnames, or other paths that traverse the cluster ingress
    - when the ingress controller is down, the app pod may only show generic
      readiness failures, 502/503s, connection refused, or timeout messages
    - the root cause is the shared ingress controller, not the app container
    """

    name = "IngressControllerUnavailable"
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
            "daemonset",
            "deployment",
        ],
    }

    blocks = [
        "ReadinessProbeFailure",
        "ProbeEndpointConnectionRefused",
        "ProbeTimeout",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
    ]

    WINDOW_MINUTES = 20
    INGRESS_IDENTIFIERS = (
        "ingress-nginx",
        "nginx-ingress",
        "ingress controller",
        "ingress-controller",
        "ingressgateway",
        "istio-ingressgateway",
        "traefik",
        "haproxy-ingress",
        "kong-proxy",
        "contour",
        "envoy-gateway",
        "alb controller",
        "aws-load-balancer-controller",
    )
    WORKLOAD_FAILURE_MARKERS = (
        "readiness probe failed",
        "readiness check failed",
        "startup dependency check failed",
        "health check failed",
        "connection refused",
        "connect: connection refused",
        "i/o timeout",
        "context deadline exceeded",
        "no route to host",
        "503",
        "502",
        "bad gateway",
        "service unavailable",
    )
    CONTROLLER_FAILURE_REASONS = {
        "backoff",
        "unhealthy",
        "failed",
        "failedscheduling",
        "killing",
    }
    CONTROLLER_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "crashloopbackoff",
        "back-off restarting failed container",
        "connection refused",
        "bind: address already in use",
        "failed to start nginx",
        "nginx reload failed",
        "configuration reload failed",
        "no endpoints available",
    )
    RECOVERY_MARKERS = (
        "readiness probe succeeded",
        "became ready",
        "started container",
        "successfully reloaded",
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

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{key}={value}".lower() for key, value in labels.items())

    def _is_ingress_object(self, obj: dict[str, Any]) -> bool:
        text = " ".join(
            value.lower()
            for value in (
                self._object_name(obj),
                self._object_namespace(obj),
                self._labels_text(obj),
                str(obj.get("metadata", {}).get("generateName") or ""),
            )
            if value
        )
        return any(identifier in text for identifier in self.INGRESS_IDENTIFIERS)

    def _event_targets_current_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind", "") or "").lower()
        if kind and kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _workload_references_ingress_dependency(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        message = self._message(event).lower()
        if any(identifier in message for identifier in self.INGRESS_IDENTIFIERS):
            return True

        for container in pod.get("spec", {}).get("containers", []) or []:
            values: list[str] = []
            for env in container.get("env", []) or []:
                value = env.get("value")
                if isinstance(value, str):
                    values.append(value)
            for field in ("command", "args"):
                for value in container.get(field, []) or []:
                    if isinstance(value, str):
                        values.append(value)
            joined = " ".join(values).lower()
            if any(identifier in joined for identifier in self.INGRESS_IDENTIFIERS):
                return True
        return False

    def _is_workload_ingress_symptom(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._event_targets_current_pod(event, pod):
            return False
        message = self._message(event).lower()
        if not any(marker in message for marker in self.WORKLOAD_FAILURE_MARKERS):
            return False
        return self._workload_references_ingress_dependency(event, pod)

    def _event_involves_ingress_controller(self, event: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        involved_text = ""
        if isinstance(involved, dict):
            involved_text = " ".join(
                str(value).lower()
                for value in (
                    involved.get("namespace"),
                    involved.get("name"),
                    involved.get("kind"),
                    involved.get("fieldPath"),
                )
                if value
            )
        if involved_text:
            return any(
                identifier in involved_text for identifier in self.INGRESS_IDENTIFIERS
            )
        message = self._message(event).lower()
        return any(identifier in message for identifier in self.INGRESS_IDENTIFIERS)

    def _is_ingress_controller_failure_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_ingress_controller(event):
            return False
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        return reason in self.CONTROLLER_FAILURE_REASONS or any(
            marker in message for marker in self.CONTROLLER_FAILURE_MARKERS
        )

    def _is_ingress_controller_recovery_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_ingress_controller(event):
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.RECOVERY_MARKERS)

    def _ready_ingress_pods(self, objects: dict[str, Any]) -> list[dict[str, Any]]:
        ready: list[dict[str, Any]] = []
        for pod in objects.get("pod", {}).values():
            if not isinstance(pod, dict) or not self._is_ingress_object(pod):
                continue
            if pod.get("status", {}).get("phase") != "Running":
                continue
            conditions = pod.get("status", {}).get("conditions", []) or []
            if any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in conditions
            ):
                ready.append(pod)
        return ready

    def _degraded_ingress_pods(
        self,
        objects: dict[str, Any],
    ) -> list[dict[str, Any]]:
        degraded: list[dict[str, Any]] = []
        for pod in objects.get("pod", {}).values():
            if not isinstance(pod, dict) or not self._is_ingress_object(pod):
                continue
            status = pod.get("status", {})
            if status.get("phase") not in {"Running", "Succeeded"}:
                degraded.append(pod)
                continue

            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in status.get("conditions", []) or []
            )
            if not ready:
                degraded.append(pod)
                continue

            for container in status.get("containerStatuses", []) or []:
                waiting = (container.get("state", {}) or {}).get("waiting", {}) or {}
                if waiting.get("reason") in {
                    "CrashLoopBackOff",
                    "CreateContainerError",
                    "RunContainerError",
                    "ImagePullBackOff",
                    "ErrImagePull",
                }:
                    degraded.append(pod)
                    break
        return degraded

    def _ready_addresses_for_endpoints(self, endpoints: dict[str, Any]) -> list[str]:
        addresses: list[str] = []
        for subset in endpoints.get("subsets", []) or []:
            for address in subset.get("addresses", []) or []:
                ip = address.get("ip")
                if isinstance(ip, str) and ip:
                    addresses.append(ip)
        return addresses

    def _ingress_service_endpoint_signals(
        self,
        objects: dict[str, Any],
    ) -> tuple[list[str], dict[str, list[str]]]:
        signals: list[str] = []
        evidence: dict[str, list[str]] = {}
        services = objects.get("service", {}) or {}
        endpoints = objects.get("endpoints", {}) or {}

        for service_name, service in services.items():
            if not isinstance(service, dict) or not self._is_ingress_object(service):
                continue
            endpoint = endpoints.get(service_name)
            if not isinstance(endpoint, dict):
                continue
            if self._ready_addresses_for_endpoints(endpoint):
                continue

            message = (
                f"Ingress controller Service '{service_name}' has no ready endpoints"
            )
            signals.append(message)
            evidence[f"service:{service_name}"] = [message]
        return signals, evidence

    def _controller_recovered_after(
        self,
        timeline: Timeline,
        latest_failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_ingress_controller_recovery_event(event):
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
        recent_events = self._ordered_recent_events(timeline)
        workload_events = [
            event
            for event in recent_events
            if self._is_workload_ingress_symptom(event, pod)
        ]
        if not workload_events:
            return None

        objects = context.get("objects", {})
        controller_signals: list[str] = []
        object_evidence: dict[str, list[str]] = {}

        service_signals, service_evidence = self._ingress_service_endpoint_signals(
            objects
        )
        controller_signals.extend(service_signals)
        object_evidence.update(service_evidence)

        degraded_pods = self._degraded_ingress_pods(objects)
        ready_pods = self._ready_ingress_pods(objects)
        if degraded_pods and not ready_pods:
            pod_names = ", ".join(
                self._object_name(pod_obj) for pod_obj in degraded_pods[:3]
            )
            controller_signals.append(
                f"No ready ingress controller pods; degraded pod(s): {pod_names}"
            )
            for pod_obj in degraded_pods[:3]:
                object_evidence[f"pod:{self._object_name(pod_obj)}"] = [
                    "Ingress controller pod is not Ready during app readiness failures"
                ]

        controller_events = [
            event
            for event in recent_events
            if self._is_ingress_controller_failure_event(event)
        ]
        if controller_events:
            representative_controller = controller_events[-1]
            controller_signals.append(
                f"Recent ingress controller event: {self._message(representative_controller)}"
            )
            object_evidence.setdefault("timeline:ingress_controller", []).append(
                self._message(representative_controller)
            )

        if not controller_signals:
            return None

        latest_failure_at = (
            self._event_time(controller_events[-1]) if controller_events else None
        )
        if controller_events and self._controller_recovered_after(
            timeline,
            latest_failure_at,
        ):
            return None

        workload_occurrences = sum(
            self._occurrences(event) for event in workload_events
        )
        controller_occurrences = sum(
            self._occurrences(event) for event in controller_events
        )
        duration_seconds = timeline.duration_between(
            lambda event: self._is_workload_ingress_symptom(event, pod)
            or self._is_ingress_controller_failure_event(event)
        )

        return {
            "representative_workload_message": self._message(workload_events[-1]),
            "workload_occurrences": workload_occurrences,
            "controller_occurrences": controller_occurrences,
            "controller_signals": list(dict.fromkeys(controller_signals)),
            "object_evidence": object_evidence,
            "duration_seconds": duration_seconds,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("IngressControllerUnavailable requires Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "IngressControllerUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_READINESS_DEPENDS_ON_INGRESS",
                    message="Application readiness depends on ingress-controller managed routes or callbacks",
                    role="runtime_context",
                ),
                Cause(
                    code="INGRESS_CONTROLLER_UNAVAILABLE",
                    message="Ingress controller has no ready serving endpoints or is failing health checks",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="APPLICATION_READINESS_BLOCKED",
                    message="Application readiness check fails because the ingress dependency is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} has readiness failures tied to an ingress dependency",
            f"Representative workload readiness failure: {candidate['representative_workload_message']}",
            f"Observed {candidate['workload_occurrences']} ingress-dependent readiness failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            "Ingress controller degradation is evidenced separately from the app readiness symptom",
        ]
        evidence.extend(candidate["controller_signals"])
        if candidate["controller_occurrences"]:
            evidence.append(
                f"Observed {candidate['controller_occurrences']} ingress controller failure event occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )
        if candidate["duration_seconds"]:
            evidence.append(
                f"Ingress controller and workload readiness failure signals persisted for {candidate['duration_seconds']/60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                candidate["representative_workload_message"],
            ],
            **candidate["object_evidence"],
        }

        return {
            "root_cause": "Ingress controller is unavailable and blocking application readiness",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Ingress controller pods are crashlooping, failing probes, or not Ready",
                "The ingress controller Service has no ready endpoints",
                "Ingress controller reload or listener startup failed after a configuration change",
                "The application readiness check depends on an ingress-managed callback, route, or public URL",
            ],
            "suggested_checks": [
                "kubectl get pods -A | grep -E 'ingress|traefik|gateway'",
                "kubectl describe service ingress-nginx-controller -n ingress-nginx",
                "kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller --tail=100",
                "Check ingress controller readiness/liveness probe events and endpoint availability",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
