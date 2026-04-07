from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
    pod_has_sidecar_injection_signal,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class ServiceMeshSidecarNetworkBlockRule(FailureRule):
    """
    Detects injected service-mesh sidecars that intercept pod traffic before
    the proxy becomes ready, causing downstream application probe or network
    failures.

    Real-world interpretation:
    - a mesh proxy sidecar such as Istio/Linkerd/Consul Envoy is present
    - the sidecar stays running but not ready because its admin readiness,
      xDS bootstrap, or certificate/control-plane state has not converged
    - application health checks begin failing only after the sidecar issue,
      which is typical when traffic capture is active before the proxy is
      ready to forward requests

    Exclusions:
    - sidecar injection failures where the proxy never appears in the pod
    - crashlooping sidecars, which are handled by sidecar-specific rules
    - generic app-only probe failures with no mesh-sidecar precursor
    """

    name = "ServiceMeshSidecarNetworkBlock"
    category = "Compound"
    priority = 69
    deterministic = False

    phases = ["Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
    ]

    WINDOW_MINUTES = 20
    MAX_SIDECAR_TO_APP_GAP = timedelta(minutes=4)
    MIN_SEQUENCE_OCCURRENCES = 2
    CACHE_KEY = "_service_mesh_sidecar_network_block_candidate"

    MESH_CONTAINER_HINTS = {
        "istio-proxy",
        "linkerd-proxy",
        "consul-connect-envoy",
        "envoy",
    }

    MESH_SIDECAR_EVENT_MARKERS = (
        "envoy proxy is not ready",
        "config not received from pilot",
        "config not received from istiod",
        "proxy is not ready",
        "failed to connect to discovery address",
        "readiness probe failed",
        "xds proxy",
        "workload certificate",
        "failed to fetch workload certificate",
        "transport is closing",
        "certificate is not available",
        "15021",
        "15020",
        "4191",
    )

    APP_IMPACT_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "http probe failed with statuscode: 503",
        "http probe failed with statuscode: 500",
        "upstream connect error",
        "disconnect/reset before headers",
        "connection failure",
        "connection reset",
        "service unavailable",
    )

    PROBE_KIND_MARKERS = {
        "readiness": "readiness probe",
        "liveness": "liveness probe",
        "startup": "startup probe",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_start(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_start(item[1]) is None else 0,
                    self._event_start(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        lowered = container_name.lower()
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path:
                return lowered in field_path

        message = self._event_message(event)
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"failed container {lowered}",
            f"containers{{{lowered}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True
        return assume_single_container and "container " not in message

    def _is_mesh_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        if not is_recognized_sidecar_container(pod, container_name):
            return False
        lowered = container_name.lower()
        if lowered in self.MESH_CONTAINER_HINTS:
            return True
        if pod_has_sidecar_injection_signal(pod) and (
            "proxy" in lowered or "envoy" in lowered
        ):
            return True
        return False

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

    def _sidecar_not_crashlooping(self, status: dict[str, Any]) -> bool:
        state = status.get("state", {}) or {}
        waiting = state.get("waiting", {}) or {}
        if waiting.get("reason") == "CrashLoopBackOff":
            return False
        return "running" in state or not waiting

    def _sidecar_issue_event(
        self,
        event: dict[str, Any],
        *,
        sidecar_name: str,
        assume_single_sidecar: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False
        if self._event_reason(event) not in {"unhealthy", "failed"}:
            return False
        if not self._container_event_match(
            event,
            sidecar_name,
            assume_single_container=assume_single_sidecar,
        ):
            return False
        message = self._event_message(event)
        return any(marker in message for marker in self.MESH_SIDECAR_EVENT_MARKERS)

    def _probe_kind(self, message: str) -> str | None:
        for kind, marker in self.PROBE_KIND_MARKERS.items():
            if marker in message:
                return kind
        return None

    def _app_impact_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_primary: bool,
    ) -> str | None:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None
        if self._event_reason(event) not in {"unhealthy", "failed"}:
            return None
        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_primary,
        ):
            return None

        message = self._event_message(event)
        if not any(marker in message for marker in self.APP_IMPACT_MARKERS):
            return None
        return self._probe_kind(message) or "network"

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None
        if not pod_has_sidecar_injection_signal(pod):
            return None

        sidecars = [
            status
            for status in self._mesh_sidecar_statuses(pod)
            if not bool(status.get("ready", False))
            and self._sidecar_not_crashlooping(status)
        ]
        primaries = [
            status
            for status in self._primary_statuses(pod)
            if not bool(status.get("ready", False))
        ]
        if not sidecars or not primaries:
            return None

        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        assume_single_sidecar = len(sidecars) == 1
        assume_single_primary = len(primaries) == 1

        best: dict[str, Any] | None = None
        for sidecar in sidecars:
            sidecar_name = str(sidecar.get("name", ""))
            sidecar_events = [
                event
                for event in ordered
                if self._sidecar_issue_event(
                    event,
                    sidecar_name=sidecar_name,
                    assume_single_sidecar=assume_single_sidecar,
                )
            ]
            if not sidecar_events:
                continue

            for primary in primaries:
                primary_name = str(primary.get("name", ""))
                sequences: list[dict[str, Any]] = []

                for sidecar_event in sidecar_events:
                    sidecar_start = self._event_start(sidecar_event)
                    if sidecar_start is None:
                        continue

                    for app_event in ordered:
                        app_start = self._event_start(app_event)
                        if app_start is None or app_start < sidecar_start:
                            continue
                        if app_start - sidecar_start > self.MAX_SIDECAR_TO_APP_GAP:
                            break

                        impact_kind = self._app_impact_event(
                            app_event,
                            container_name=primary_name,
                            assume_single_primary=assume_single_primary,
                        )
                        if impact_kind is None:
                            continue

                        sequences.append(
                            {
                                "sidecar_event": sidecar_event,
                                "app_event": app_event,
                                "impact_kind": impact_kind,
                                "strength": min(
                                    self._occurrences(sidecar_event),
                                    self._occurrences(app_event),
                                ),
                            }
                        )
                        break

                total_strength = sum(seq["strength"] for seq in sequences)
                if (
                    len(sequences) < self.MIN_SEQUENCE_OCCURRENCES
                    and total_strength < self.MIN_SEQUENCE_OCCURRENCES
                ):
                    continue

                dominant = max(
                    sequences,
                    key=lambda seq: (
                        seq["strength"],
                        self._occurrences(seq["app_event"]),
                    ),
                )
                candidate = {
                    "sidecar": sidecar,
                    "primary": primary,
                    "sequences": sequences,
                    "total_strength": total_strength,
                    "impact_kind": dominant["impact_kind"],
                    "sidecar_message": str(
                        dominant["sidecar_event"].get("message", "")
                    ).strip(),
                    "app_message": str(
                        dominant["app_event"].get("message", "")
                    ).strip(),
                }

                if best is None or (
                    candidate["total_strength"],
                    len(candidate["sequences"]),
                ) > (
                    best["total_strength"],
                    len(best["sequences"]),
                ):
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError(
                "ServiceMeshSidecarNetworkBlock explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        sidecar_name = str(candidate["sidecar"].get("name", "<sidecar>"))
        primary_name = str(candidate["primary"].get("name", "<container>"))
        impact_kind = str(candidate["impact_kind"])
        sidecar_restart_count = int(candidate["sidecar"].get("restartCount", 0) or 0)
        sidecar_state = candidate["sidecar"].get("state", {}) or {}
        sidecar_state_name = (
            "running"
            if "running" in sidecar_state
            else "waiting" if "waiting" in sidecar_state else "unknown"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_MESH_SIDECAR_PRESENT",
                    message=f"Pod includes injected service-mesh sidecar '{sidecar_name}' that mediates pod traffic",
                    role="network_context",
                ),
                Cause(
                    code="SIDECAR_PROXY_NOT_READY",
                    message=f"Service-mesh sidecar '{sidecar_name}' is intercepting traffic before the proxy is ready to forward it",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="APPLICATION_TRAFFIC_BLOCKED_BY_SIDECAR",
                    message=f"Application container '{primary_name}' then develops {impact_kind}-level network/probe failures after the sidecar issue appears",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Service mesh sidecar is blocking pod traffic before the proxy becomes ready",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Recognized service-mesh sidecar '{sidecar_name}' is present and currently Ready=False with state={sidecar_state_name} restartCount={sidecar_restart_count}",
                f"Timeline shows {len(candidate['sequences'])} sidecar-network-issue -> application-impact sequence(s) within the last {self.WINDOW_MINUTES} minutes",
                f"Representative sidecar issue: {candidate['sidecar_message']}",
                f"Representative application impact: {candidate['app_message']}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Application network symptoms begin only after the service-mesh sidecar becomes not ready"
                ],
                f"container:{sidecar_name}": [
                    candidate["sidecar_message"],
                ],
                f"container:{primary_name}": [
                    candidate["app_message"],
                ],
            },
            "likely_causes": [
                "The mesh sidecar has not received valid xDS/bootstrap configuration from the control plane",
                "mTLS certificates or service-mesh identity bootstrap are missing or stale, leaving the proxy unready",
                "Probe rewriting or traffic capture is active before the sidecar can forward application traffic",
                "The service-mesh control plane is degraded, so the sidecar intercepts traffic but cannot program listeners or clusters",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name}",
                "Inspect service-mesh control-plane health and proxy synchronization status",
                "Review mesh probe-rewrite and sidecar bootstrap annotations on the pod",
            ],
        }
