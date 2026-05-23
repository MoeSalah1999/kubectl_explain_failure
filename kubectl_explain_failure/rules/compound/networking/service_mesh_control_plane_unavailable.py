from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
    pod_has_sidecar_injection_signal,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class ServiceMeshControlPlaneUnavailableRule(FailureRule):
    """
    Detects workload mesh-sidecar failures whose root cause is an unavailable
    service-mesh control plane.

    Real-world behavior:
    - sidecars such as Istio Envoy, Linkerd proxy, or Consul Connect Envoy
      can start and intercept traffic before they have valid xDS/service
      discovery, identity, or certificate state
    - the workload pod often only shows sidecar readiness failures and app
      probe failures, while the real root cause is istiod/linkerd-destination/
      consul control-plane unavailability
    - the mesh control-plane Service commonly has no ready endpoints, or the
      control-plane Deployment/Pods are unavailable during the same incident
    """

    name = "ServiceMeshControlPlaneUnavailable"
    category = "Compound"
    severity = "High"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "service",
            "endpoints",
            "endpointslice",
            "deployment",
            "pod",
        ],
    }

    blocks = [
        "ServiceMeshSidecarNetworkBlock",
        "SidecarCrashLoop",
        "SidecarStartupTimeout",
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
        "DeploymentReplicaMismatch",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 20
    MESH_SIDECAR_NAMES = {
        "istio-proxy",
        "linkerd-proxy",
        "consul-connect-envoy",
        "envoy",
    }
    CONTROL_PLANE_IDENTIFIERS = (
        "istiod",
        "pilot",
        "istio-system",
        "linkerd-destination",
        "linkerd-identity",
        "linkerd-proxy-injector",
        "linkerd-control-plane",
        "consul-server",
        "consul-connect-injector",
        "consul-controller",
        "mesh control plane",
        "service mesh control plane",
    )
    SIDECAR_CONTROL_PLANE_MARKERS = (
        "config not received from pilot",
        "config not received from istiod",
        "failed to connect to discovery address",
        "xds connection",
        "ads connection",
        "xds proxy",
        "transport is closing",
        "connection refused",
        "no healthy upstream",
        "workload certificate",
        "failed to fetch workload certificate",
        "certificate is not available",
        "sds",
        "identity service",
        "destination service",
    )
    APP_IMPACT_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "http probe failed with statuscode: 503",
        "upstream connect error",
        "disconnect/reset before headers",
        "service unavailable",
    )
    CONTROL_PLANE_FAILURE_REASONS = {
        "backoff",
        "unhealthy",
        "failed",
        "failedscheduling",
        "failedmount",
        "killing",
    }
    CONTROL_PLANE_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "crashloopbackoff",
        "back-off restarting failed container",
        "connection refused",
        "context deadline exceeded",
        "no endpoints available",
        "endpoints not found",
        "service unavailable",
        "http probe failed with statuscode: 503",
        "failed to serve discovery",
        "failed to create discovery service",
        "xds",
        "grpc",
    )
    RECOVERY_REASONS = {
        "Started",
        "Pulled",
        "Created",
        "Ready",
    }
    RECOVERY_MARKERS = (
        "became ready",
        "readiness probe succeeded",
        "successfully synced",
        "started container",
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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "")
        return str(source or "")

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

    def _is_mesh_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        lowered = container_name.lower()
        if lowered in self.MESH_SIDECAR_NAMES:
            return True
        if not is_recognized_sidecar_container(pod, container_name):
            return False
        return pod_has_sidecar_injection_signal(pod) and (
            "proxy" in lowered or "envoy" in lowered
        )

    def _mesh_sidecar_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if self._is_mesh_sidecar(pod, str(status.get("name", "")))
        ]

    def _primary_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if not self._is_mesh_sidecar(pod, str(status.get("name", "")))
        ]

    def _container_event_match(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
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

            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path:
                return container_name.lower() in field_path

        message = self._message(event).lower()
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True
        return assume_single_container and "container " not in message

    def _is_sidecar_control_plane_symptom(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        sidecar_name: str,
        *,
        assume_single_sidecar: bool,
    ) -> bool:
        if not self._container_event_match(
            event,
            pod,
            sidecar_name,
            assume_single_container=assume_single_sidecar,
        ):
            return False
        reason = self._reason(event).lower()
        if reason not in {"failed", "unhealthy", "backoff"}:
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.SIDECAR_CONTROL_PLANE_MARKERS)

    def _is_app_impact_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        container_name: str,
        *,
        assume_single_primary: bool,
    ) -> bool:
        if not self._container_event_match(
            event,
            pod,
            container_name,
            assume_single_container=assume_single_primary,
        ):
            return False
        reason = self._reason(event).lower()
        if reason not in {"failed", "unhealthy"}:
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.APP_IMPACT_MARKERS)

    def _is_control_plane_object(self, obj: dict[str, Any]) -> bool:
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
        return any(identifier in text for identifier in self.CONTROL_PLANE_IDENTIFIERS)

    def _ready_addresses_for_endpoints(self, endpoints: dict[str, Any]) -> list[str]:
        addresses: list[str] = []
        for subset in endpoints.get("subsets", []) or []:
            for address in subset.get("addresses", []) or []:
                ip = address.get("ip")
                if isinstance(ip, str) and ip:
                    addresses.append(ip)
        return addresses

    def _control_plane_service_signals(
        self,
        objects: dict[str, Any],
    ) -> tuple[list[str], dict[str, list[str]]]:
        signals: list[str] = []
        evidence: dict[str, list[str]] = {}
        endpoints = objects.get("endpoints", {}) or {}

        for service_name, service in (objects.get("service", {}) or {}).items():
            if not isinstance(service, dict) or not self._is_control_plane_object(
                service
            ):
                continue

            endpoint = endpoints.get(service_name)
            if not isinstance(endpoint, dict):
                continue
            if self._ready_addresses_for_endpoints(endpoint):
                continue

            message = (
                f"Mesh control-plane Service '{service_name}' has no ready endpoints"
            )
            signals.append(message)
            evidence[f"service:{service_name}"] = [message]

        return signals, evidence

    def _control_plane_deployment_signals(
        self,
        objects: dict[str, Any],
    ) -> tuple[list[str], dict[str, list[str]]]:
        signals: list[str] = []
        evidence: dict[str, list[str]] = {}
        for deployment_name, deployment in (
            objects.get("deployment", {}) or {}
        ).items():
            if not isinstance(deployment, dict) or not self._is_control_plane_object(
                deployment
            ):
                continue
            spec = deployment.get("spec", {}) or {}
            status = deployment.get("status", {}) or {}
            desired = int(spec.get("replicas", status.get("replicas", 0)) or 0)
            available = int(status.get("availableReplicas", 0) or 0)
            unavailable = int(status.get("unavailableReplicas", 0) or 0)
            available_false = any(
                condition.get("type") == "Available"
                and condition.get("status") == "False"
                for condition in status.get("conditions", []) or []
            )
            if desired <= 0 or (available > 0 and not available_false):
                continue

            message = (
                f"Mesh control-plane Deployment '{deployment_name}' has desired={desired}, "
                f"available={available}, unavailable={unavailable}"
            )
            signals.append(message)
            evidence[f"deployment:{deployment_name}"] = [message]

        return signals, evidence

    def _control_plane_pod_signals(
        self,
        objects: dict[str, Any],
    ) -> tuple[list[str], dict[str, list[str]]]:
        degraded: list[dict[str, Any]] = []
        ready: list[dict[str, Any]] = []
        for pod in (objects.get("pod", {}) or {}).values():
            if not isinstance(pod, dict) or not self._is_control_plane_object(pod):
                continue
            status = pod.get("status", {}) or {}
            is_ready = status.get("phase") == "Running" and any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in status.get("conditions", []) or []
            )
            if is_ready:
                ready.append(pod)
            else:
                degraded.append(pod)

        if not degraded or ready:
            return [], {}

        pod_names = ", ".join(self._object_name(pod) for pod in degraded[:3])
        signal = f"No ready mesh control-plane pods; degraded pod(s): {pod_names}"
        evidence = {
            f"pod:{self._object_name(pod)}": [
                "Mesh control-plane pod is not Ready while sidecars cannot sync"
            ]
            for pod in degraded[:3]
        }
        return [signal], evidence

    def _event_involves_control_plane(self, event: dict[str, Any]) -> bool:
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
                    identifier in involved_text
                    for identifier in self.CONTROL_PLANE_IDENTIFIERS
                )

        text = (
            f"{self._source_component(event).lower()} "
            f"{self._message(event).lower()}"
        )
        return any(identifier in text for identifier in self.CONTROL_PLANE_IDENTIFIERS)

    def _is_control_plane_failure_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_control_plane(event):
            return False
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        return reason in self.CONTROL_PLANE_FAILURE_REASONS or any(
            marker in message for marker in self.CONTROL_PLANE_FAILURE_MARKERS
        )

    def _is_control_plane_recovery_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_control_plane(event):
            return False
        reason = self._reason(event)
        message = self._message(event).lower()
        return reason in self.RECOVERY_REASONS or any(
            marker in message for marker in self.RECOVERY_MARKERS
        )

    def _control_plane_recovered_after(
        self,
        timeline: Timeline,
        failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_control_plane_recovery_event(event):
                continue
            event_at = self._event_time(event)
            if failure_at is None or event_at is None or event_at >= failure_at:
                return True
        return False

    def _control_plane_and_sidecar_duration(
        self,
        timeline: Timeline,
        sidecar_events: list[dict[str, Any]],
    ) -> float:
        sidecar_event_ids = {id(event) for event in sidecar_events}

        def is_relevant_event(event: dict[str, Any]) -> bool:
            return (
                self._is_control_plane_failure_event(event)
                or id(event) in sidecar_event_ids
            )

        return timeline.duration_between(is_relevant_event)

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not pod_has_sidecar_injection_signal(pod):
            return None

        recent_events = self._ordered_recent_events(timeline)
        sidecars = self._mesh_sidecar_statuses(pod)
        primaries = self._primary_statuses(pod)
        if not sidecars:
            return None

        assume_single_sidecar = len(sidecars) == 1
        assume_single_primary = len(primaries) == 1

        sidecar_events: list[dict[str, Any]] = []
        sidecar_name = str(sidecars[0].get("name", "<sidecar>"))
        for sidecar in sidecars:
            candidate_name = str(sidecar.get("name", ""))
            matches = [
                event
                for event in recent_events
                if self._is_sidecar_control_plane_symptom(
                    event,
                    pod,
                    candidate_name,
                    assume_single_sidecar=assume_single_sidecar,
                )
            ]
            if matches:
                sidecar_events = matches
                sidecar_name = candidate_name
                break

        if not sidecar_events:
            return None

        app_events: list[dict[str, Any]] = []
        primary_name = str(primaries[0].get("name", "<container>")) if primaries else ""
        for primary in primaries:
            candidate_name = str(primary.get("name", ""))
            matches = [
                event
                for event in recent_events
                if self._is_app_impact_event(
                    event,
                    pod,
                    candidate_name,
                    assume_single_primary=assume_single_primary,
                )
            ]
            if matches:
                app_events = matches
                primary_name = candidate_name
                break

        objects = context.get("objects", {}) or {}
        control_plane_signals: list[str] = []
        object_evidence: dict[str, list[str]] = {}

        for signal_func in (
            self._control_plane_service_signals,
            self._control_plane_deployment_signals,
            self._control_plane_pod_signals,
        ):
            signals, evidence = signal_func(objects)
            control_plane_signals.extend(signals)
            object_evidence.update(evidence)

        control_plane_events = [
            event
            for event in recent_events
            if self._is_control_plane_failure_event(event)
        ]
        if control_plane_events:
            representative = control_plane_events[-1]
            message = (
                f"Recent mesh control-plane event: {self._message(representative)}"
            )
            control_plane_signals.append(message)
            object_evidence.setdefault("timeline:mesh_control_plane", []).append(
                self._message(representative)
            )

        if not control_plane_signals:
            return None

        latest_failure_at = (
            self._event_time(control_plane_events[-1]) if control_plane_events else None
        )
        if control_plane_events and self._control_plane_recovered_after(
            timeline,
            latest_failure_at,
        ):
            return None

        sidecar_occurrences = sum(self._occurrences(event) for event in sidecar_events)
        control_plane_occurrences = sum(
            self._occurrences(event) for event in control_plane_events
        )
        duration_seconds = self._control_plane_and_sidecar_duration(
            timeline,
            sidecar_events,
        )

        return {
            "sidecar_name": sidecar_name,
            "primary_name": primary_name,
            "representative_sidecar_message": self._message(sidecar_events[-1]),
            "representative_app_message": (
                self._message(app_events[-1]) if app_events else ""
            ),
            "sidecar_occurrences": sidecar_occurrences,
            "control_plane_occurrences": control_plane_occurrences,
            "control_plane_signals": list(dict.fromkeys(control_plane_signals)),
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
            raise ValueError(
                "ServiceMeshControlPlaneUnavailable requires Timeline context"
            )

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "ServiceMeshControlPlaneUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        sidecar_name = candidate["sidecar_name"]
        primary_name = candidate["primary_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_USES_SERVICE_MESH_SIDECAR",
                    message=f"Pod includes service-mesh sidecar '{sidecar_name}' that depends on mesh control-plane state",
                    role="network_context",
                ),
                Cause(
                    code="SERVICE_MESH_CONTROL_PLANE_UNAVAILABLE",
                    message="The mesh control plane has no ready serving endpoints or is failing health checks",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SIDECAR_CANNOT_SYNC_MESH_CONFIG",
                    message=f"Sidecar '{sidecar_name}' cannot receive mesh configuration, identity, or discovery updates",
                    role="network_intermediate",
                ),
                Cause(
                    code="APPLICATION_TRAFFIC_BLOCKED_BY_MESH",
                    message="Application traffic or probes are blocked while the sidecar is unsynchronized",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} has a service-mesh sidecar reporting control-plane sync failure",
            f"Representative sidecar control-plane failure: {candidate['representative_sidecar_message']}",
            f"Observed {candidate['sidecar_occurrences']} sidecar control-plane sync failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            "Mesh control-plane degradation is evidenced separately from the workload sidecar symptom",
        ]
        if candidate["representative_app_message"]:
            evidence.append(
                f"Representative application impact: {candidate['representative_app_message']}"
            )
        evidence.extend(candidate["control_plane_signals"])
        if candidate["control_plane_occurrences"]:
            evidence.append(
                f"Observed {candidate['control_plane_occurrences']} mesh control-plane failure event occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )
        if candidate["duration_seconds"]:
            evidence.append(
                f"Mesh control-plane and sidecar sync failures persisted for {candidate['duration_seconds']/60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                candidate["representative_sidecar_message"],
            ],
            f"container:{sidecar_name}": [
                "Sidecar cannot sync mesh configuration from the control plane"
            ],
            **candidate["object_evidence"],
        }
        if primary_name and candidate["representative_app_message"]:
            object_evidence[f"container:{primary_name}"] = [
                candidate["representative_app_message"]
            ]

        return {
            "root_cause": "Service mesh control plane is unavailable and blocking sidecar traffic",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Mesh control-plane pods are crashlooping, failing probes, or not Ready",
                "The mesh control-plane Service has no ready endpoints for sidecar xDS or identity traffic",
                "Control-plane certificate, discovery, or webhook components are unavailable",
                "A control-plane rollout or configuration change broke sidecar discovery and identity sync",
            ],
            "suggested_checks": [
                "kubectl get pods -n istio-system -l app=istiod -o wide",
                "kubectl get endpoints istiod -n istio-system",
                "kubectl logs -n istio-system deploy/istiod --tail=100",
                f"kubectl logs {pod_name} -n {namespace} -c {sidecar_name}",
                "Check mesh proxy sync status and control-plane readiness before debugging the app container",
            ],
        }
