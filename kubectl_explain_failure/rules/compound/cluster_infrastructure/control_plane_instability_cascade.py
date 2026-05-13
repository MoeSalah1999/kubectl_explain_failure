from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ControlPlaneInstabilityCascadeRule(FailureRule):
    """
    Detects a real control-plane instability cascade rather than a localized
    component blip.

    Real-world behavior:
    - a single kube-apiserver probe failure, scheduler lease retry, or
      controller-manager restart can happen during normal maintenance
    - a cascade is higher confidence when multiple control-plane components
      are degraded in the same incident window and emit corroborating API,
      lease, health, or etcd failure signals
    - workload symptoms such as stuck rollouts or unscheduled pods are treated
      as downstream effects of the unstable control plane
    """

    name = "ControlPlaneInstabilityCascade"
    category = "Compound"
    priority = 92
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["pod"],
        "context": ["timeline"],
        "optional_objects": [
            "deployment",
            "replicaset",
            "statefulset",
            "daemonset",
            "service",
            "endpoints",
            "endpointslice",
            "node",
        ],
    }
    blocks = [
        "APIServerUnreachable",
        "ControllerManagerLeaderElectionFailure",
        "ControllerManagerUnavailable",
        "SchedulerLeaderElectionFailure",
        "DeploymentReplicaMismatch",
        "DeploymentProgressDeadlineExceeded",
        "DeploymentRolloutStalled",
        "FailedScheduling",
        "PendingUnschedulable",
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
        "SchedulingFlapping",
        "SchedulingTimeoutExceeded",
    ]

    WINDOW_MINUTES = 20
    MIN_COMPONENTS = 2
    MIN_EVENTS = 3
    MIN_SPAN_SECONDS = 120
    CACHE_KEY = "_control_plane_instability_cascade_candidate"

    COMPONENT_MARKERS = {
        "apiserver": ("kube-apiserver", " apiserver", "apiserver-"),
        "controller-manager": (
            "kube-controller-manager",
            "controller-manager",
        ),
        "scheduler": ("kube-scheduler", " scheduler", "scheduler-"),
        "etcd": ("etcd",),
    }
    COMPONENT_DISPLAY = {
        "apiserver": "kube-apiserver",
        "controller-manager": "kube-controller-manager",
        "scheduler": "kube-scheduler",
        "etcd": "etcd",
    }
    FAILURE_REASONS = {
        "backoff",
        "failed",
        "failedscheduling",
        "failedleaderelection",
        "leaderelection",
        "unhealthy",
    }
    BENIGN_MARKERS = (
        "successfully acquired lease",
        "became leader",
        "new leader elected",
        "attempting to acquire leader lease",
    )
    FAILURE_MARKERS = (
        "/readyz",
        "/livez",
        "/healthz",
        "connection refused",
        "context deadline exceeded",
        "dial tcp",
        "etcdserver:",
        "failed to renew lease",
        "failed to acquire lease",
        "failed to update lock",
        "health check failed",
        "i/o timeout",
        "leader election lost",
        "leaderelection lost",
        "leadership lost",
        "no route to host",
        "server was unable to return a response",
        "stopped leading",
        "the connection to the server",
        "tls handshake timeout",
        "too many requests",
        "unable to connect to the server",
    )
    APISERVER_REQUIRED_MARKERS = (
        "apiserver",
        "kube-apiserver",
        "kubernetes.default.svc",
        "127.0.0.1:6443",
        "localhost:6443",
        "6443",
        "etcdserver:",
    )

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _ordered_recent(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        return [
            event
            for _, event in sorted(
                enumerate(recent),
                key=lambda item: (
                    1 if self._event_ts(item[1]) is None else 0,
                    self._event_ts(item[1])
                    or datetime.min.replace(tzinfo=timezone.utc),
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "") or "").strip()

    def _message_lower(self, event: dict[str, Any]) -> str:
        return self._message(event).lower()

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "") or "").lower()

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "") or "").lower()
        return str(source or "").lower()

    def _pod_text(self, pod_obj: dict[str, Any]) -> str:
        metadata = pod_obj.get("metadata", {}) or {}
        labels = metadata.get("labels", {}) or {}
        spec = pod_obj.get("spec", {}) or {}
        status = pod_obj.get("status", {}) or {}
        values = [
            metadata.get("name", ""),
            metadata.get("namespace", ""),
            labels.get("component", ""),
            labels.get("tier", ""),
            *labels.keys(),
            *labels.values(),
            *[
                c.get("name", "")
                for c in spec.get("containers", []) or []
                if isinstance(c, dict)
            ],
            *[
                c.get("name", "")
                for c in status.get("containerStatuses", []) or []
                if isinstance(c, dict)
            ],
        ]
        return " ".join(str(value).lower() for value in values if value)

    def _component_for_pod(self, pod_obj: dict[str, Any]) -> str | None:
        if pod_obj.get("metadata", {}).get("namespace") != "kube-system":
            return None
        text = self._pod_text(pod_obj)
        for component, markers in self.COMPONENT_MARKERS.items():
            if any(marker in text for marker in markers):
                return component
        return None

    def _component_for_event(self, event: dict[str, Any]) -> str | None:
        text = " ".join(
            [
                self._source_component(event),
                str((event.get("involvedObject", {}) or {}).get("name", "")),
                str((event.get("involvedObject", {}) or {}).get("kind", "")),
                self._message_lower(event),
            ]
        ).lower()
        for component, markers in self.COMPONENT_MARKERS.items():
            if any(marker in text for marker in markers):
                return component
        return None

    def _container_state_name(self, status: dict[str, Any]) -> str:
        state = status.get("state", {}) or {}
        if "waiting" in state:
            return "waiting"
        if "terminated" in state:
            return "terminated"
        if "running" in state:
            return "running"
        return "unknown"

    def _status_is_degraded(self, status: dict[str, Any]) -> bool:
        state = status.get("state", {}) or {}
        waiting = state.get("waiting", {}) or {}
        terminated = state.get("terminated", {}) or {}
        return (
            not bool(status.get("ready", False))
            or bool(terminated)
            or waiting.get("reason") == "CrashLoopBackOff"
            or self._as_int(status.get("restartCount"), 0) > 0
        )

    def _component_status(
        self,
        pod_obj: dict[str, Any],
        component: str,
    ) -> dict[str, Any] | None:
        marker = self.COMPONENT_DISPLAY[component]
        statuses = pod_obj.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if not isinstance(status, dict):
                continue
            if marker not in str(status.get("name", "")).lower():
                continue
            return status
        return statuses[0] if len(statuses) == 1 and component == "etcd" else None

    def _event_is_failure(self, event: dict[str, Any]) -> bool:
        message = self._message_lower(event)
        if not message or any(marker in message for marker in self.BENIGN_MARKERS):
            return False
        reason = self._reason(event)
        if reason not in self.FAILURE_REASONS and "fail" not in reason:
            return False
        return any(marker in message for marker in self.FAILURE_MARKERS)

    def _service_ready(
        self,
        objects: dict[str, Any],
        service_name: str,
        namespace: str,
    ) -> bool | None:
        service = self._find_named_object(objects, "service", service_name, namespace)
        if service is None:
            return None

        endpoints = self._find_named_object(
            objects,
            "endpoints",
            service_name,
            namespace,
        )
        if endpoints:
            for subset in endpoints.get("subsets", []) or []:
                if subset.get("addresses"):
                    return True
            return False

        for slice_obj in objects.get("endpointslice", {}).values():
            if not isinstance(slice_obj, dict):
                continue
            metadata = slice_obj.get("metadata", {}) or {}
            labels = metadata.get("labels", {}) or {}
            if metadata.get("namespace", "default") != namespace:
                continue
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            if any(
                endpoint.get("conditions", {}).get("ready") is True
                for endpoint in slice_obj.get("endpoints", []) or []
            ):
                return True
            return False

        return None

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict):
            if direct.get("metadata", {}).get("namespace", "default") == namespace:
                return direct
        for obj in objects.get(kind, {}).values():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {}) or {}
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", "default") != namespace:
                continue
            return obj
        return None

    def _owner_ref(self, obj: dict[str, Any], kind: str) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
                return str(ref["name"])
        return None

    def _workload_symptom(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, str] | None:
        objects = context.get("objects", {}) or {}
        namespace = pod.get("metadata", {}).get("namespace", "default")

        deployment_name = self._owner_ref(pod, "Deployment")
        rs_name = self._owner_ref(pod, "ReplicaSet")
        if deployment_name is None and rs_name is not None:
            rs = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs is not None:
                deployment_name = self._owner_ref(rs, "Deployment")

        if deployment_name:
            deployment = self._find_named_object(
                objects,
                "deployment",
                deployment_name,
                namespace,
            )
            if deployment:
                status = deployment.get("status", {}) or {}
                desired = self._as_int(
                    status.get(
                        "replicas",
                        deployment.get("spec", {}).get("replicas", 0),
                    ),
                    0,
                )
                available = self._as_int(status.get("availableReplicas"), 0)
                updated = self._as_int(status.get("updatedReplicas"), 0)
                if desired > 0 and (available < desired or updated < desired):
                    return {
                        "kind": "deployment",
                        "name": deployment_name,
                        "message": f"Deployment '{deployment_name}' remains at {available}/{desired} available replicas while only {updated}/{desired} replicas are updated",
                    }

        phase = str(pod.get("status", {}).get("phase", ""))
        if phase == "Pending":
            return {
                "kind": "pod",
                "name": pod.get("metadata", {}).get("name", "<pod>"),
                "message": f"Pod '{pod.get('metadata', {}).get('name', '<pod>')}' remains Pending while control-plane components are unstable",
            }

        return None

    def _component_signals(
        self,
        context: dict[str, Any],
        ordered_events: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        signals: dict[str, dict[str, Any]] = {}

        for pod_obj in objects.get("pod", {}).values():
            if not isinstance(pod_obj, dict):
                continue
            component = self._component_for_pod(pod_obj)
            if component is None:
                continue
            status = self._component_status(pod_obj, component)
            if status is None or not self._status_is_degraded(status):
                continue
            pod_name = pod_obj.get("metadata", {}).get("name", "<unknown>")
            signal = signals.setdefault(
                component,
                {
                    "pod_name": pod_name,
                    "container_name": status.get(
                        "name",
                        self.COMPONENT_DISPLAY[component],
                    ),
                    "state_name": self._container_state_name(status),
                    "restart_count": self._as_int(status.get("restartCount"), 0),
                    "events": [],
                },
            )
            if self._as_int(status.get("restartCount"), 0) > signal["restart_count"]:
                signal["restart_count"] = self._as_int(status.get("restartCount"), 0)

        for event in ordered_events:
            if not self._event_is_failure(event):
                continue
            component = self._component_for_event(event)
            if component is None:
                continue
            signal = signals.setdefault(
                component,
                {
                    "pod_name": str(
                        (event.get("involvedObject", {}) or {}).get(
                            "name",
                            self.COMPONENT_DISPLAY[component],
                        )
                    ),
                    "container_name": self.COMPONENT_DISPLAY[component],
                    "state_name": "unknown",
                    "restart_count": 0,
                    "events": [],
                },
            )
            signal["events"].append(event)

        return signals

    def _event_span_seconds(self, events: list[dict[str, Any]]) -> int:
        timestamps = [self._event_ts(event) for event in events]
        usable = [ts for ts in timestamps if ts is not None]
        if len(usable) < 2:
            return 0
        return int((max(usable) - min(usable)).total_seconds())

    def _representative_event(self, signal: dict[str, Any]) -> dict[str, Any] | None:
        events = signal.get("events", []) or []
        if not events:
            return None
        return events[-1]

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        ordered_events = self._ordered_recent(timeline)
        if not ordered_events:
            return None

        objects = context.get("objects", {}) or {}
        signals = self._component_signals(context, ordered_events)
        api_service_ready = self._service_ready(objects, "kubernetes", "default")
        if api_service_ready is False:
            signals.setdefault(
                "apiserver",
                {
                    "pod_name": "kube-apiserver",
                    "container_name": "kube-apiserver",
                    "state_name": "unknown",
                    "restart_count": 0,
                    "events": [],
                },
            )
            signals["apiserver"]["api_service_ready"] = False

        component_names = sorted(signals)
        if len(component_names) < self.MIN_COMPONENTS:
            return None

        component_events = [
            event
            for signal in signals.values()
            for event in signal.get("events", []) or []
        ]
        if len(component_events) < self.MIN_EVENTS:
            return None

        span_seconds = self._event_span_seconds(component_events)
        if span_seconds < self.MIN_SPAN_SECONDS:
            return None

        apiserver_correlated = "apiserver" in signals or any(
            any(
                marker in self._message_lower(event)
                for marker in self.APISERVER_REQUIRED_MARKERS
            )
            for event in component_events
        )
        if not apiserver_correlated:
            return None

        symptom = self._workload_symptom(pod, context)
        if symptom is None:
            return None

        return {
            "signals": signals,
            "components": component_names,
            "component_events": component_events,
            "span_seconds": span_seconds,
            "api_service_ready": api_service_ready,
            "symptom": symptom,
        }

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
                "ControlPlaneInstabilityCascade explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        components = candidate["components"]
        component_display = [
            self.COMPONENT_DISPLAY.get(component, component) for component in components
        ]
        minutes = candidate["span_seconds"] / 60.0
        symptom = candidate["symptom"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTROL_PLANE_COMPONENTS_SHARE_API_AND_ETCD_PATHS",
                    message="kube-apiserver, scheduler, and controller-manager depend on shared API, etcd, lease, and control-plane node paths",
                    role="control_plane_context",
                ),
                Cause(
                    code="CONTROL_PLANE_INSTABILITY_CASCADE",
                    message="Multiple control-plane components are failing in the same incident window",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTROLLERS_AND_SCHEDULER_LOSE_PROGRESS",
                    message="Controllers and scheduler cannot reliably renew leases, reach the API, or reconcile workload state",
                    role="controller_intermediate",
                ),
                Cause(
                    code="WORKLOAD_PROGRESS_STALLED",
                    message=symptom["message"],
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Control-plane components degraded together: {', '.join(component_display)}",
            f"Control-plane failure events span {minutes:.1f} minutes across {len(candidate['component_events'])} corroborating events",
            symptom["message"],
        ]
        if candidate["api_service_ready"] is False:
            evidence.append(
                "Kubernetes service 'kubernetes' currently has no ready API endpoints"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [
                "The pod is a downstream workload symptom while control-plane components are unstable"
            ],
            f"{symptom['kind']}:{symptom['name']}": [symptom["message"]],
        }

        for component in components:
            signal = candidate["signals"][component]
            display = self.COMPONENT_DISPLAY.get(component, component)
            key = f"pod:{signal['pod_name']}"
            object_items = [
                f"{display} state={signal['state_name']} restartCount={signal['restart_count']}",
            ]
            representative = self._representative_event(signal)
            if representative is not None:
                object_items.append(self._message(representative))
            elif signal.get("api_service_ready") is False:
                object_items.append("kubernetes Service has no ready API endpoints")
            object_evidence[key] = object_items

        if candidate["api_service_ready"] is False:
            object_evidence["service:kubernetes"] = [
                "No ready endpoints back the Kubernetes API Service VIP"
            ]

        confidence = 0.94
        if len(components) >= 3:
            confidence = 0.97
        if candidate["api_service_ready"] is False:
            confidence = min(0.99, confidence + 0.01)

        return {
            "root_cause": "Control-plane instability cascade is preventing controllers and scheduler from making progress",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "etcd latency, quorum loss, or disk pressure is making kube-apiserver and leader-election writes unreliable",
                "Control-plane node network or host-resource pressure is causing API, scheduler, and controller-manager health checks to fail together",
                "The Kubernetes API endpoint or Service VIP is intermittently unreachable from control-plane components",
                "Certificate, manifest, or static-pod configuration drift affected multiple control-plane components during the same incident",
            ],
            "suggested_checks": [
                "kubectl get pods -n kube-system -l tier=control-plane -o wide",
                "kubectl get endpoints kubernetes -n default -o yaml",
                "kubectl get lease -n kube-system",
                "kubectl logs -n kube-system -l component=kube-apiserver --tail=200",
                "kubectl logs -n kube-system -l component=kube-controller-manager --tail=200",
                "kubectl logs -n kube-system -l component=kube-scheduler --tail=200",
                "Check etcd health, control-plane node pressure, and API server /readyz",
            ],
        }
