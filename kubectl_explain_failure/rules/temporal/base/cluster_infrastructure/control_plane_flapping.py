from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ControlPlaneFlappingRule(FailureRule):
    """
    Detects repeated control-plane failure/recovery cycles.

    Real-world behavior:
    - healthy HA control planes can emit occasional standby lease-acquisition
      noise, so a single leader-election event is not enough
    - actionable flapping has both failure and recovery transitions, usually
      across kube-apiserver plus another control-plane component
    - the symptom is intermittent workload progress, not a single permanent
      component outage
    """

    name = "ControlPlaneFlapping"
    category = "Temporal"
    priority = 78
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pod"],
        "optional_objects": [
            "deployment",
            "replicaset",
            "service",
            "endpoints",
            "endpointslice",
        ],
    }
    blocks = [
        "APIServerUnreachable",
        "ControllerManagerLeaderElectionFailure",
        "ControllerManagerUnavailable",
        "SchedulerLeaderElectionFailure",
        "DeploymentReplicaMismatch",
        "FailedScheduling",
        "PendingUnschedulable",
        "LivenessProbeFailure",
        "ReadinessProbeFailure",
        "SchedulingFlapping",
        "SchedulingTimeoutExceeded",
        "StartupProbeFailure",
    ]

    WINDOW_MINUTES = 30
    MIN_COMPONENTS = 2
    MIN_TRANSITIONS = 4
    MIN_FAILURES = 2
    MIN_RECOVERIES = 2
    MIN_DURATION_SECONDS = 300
    CACHE_KEY = "_control_plane_flapping_candidate"

    COMPONENT_MARKERS = {
        "apiserver": ("kube-apiserver", " apiserver", "apiserver-"),
        "controller-manager": ("kube-controller-manager", "controller-manager"),
        "scheduler": ("kube-scheduler", " scheduler", "scheduler-"),
    }
    COMPONENT_DISPLAY = {
        "apiserver": "kube-apiserver",
        "controller-manager": "kube-controller-manager",
        "scheduler": "kube-scheduler",
    }
    FAILURE_REASONS = {
        "failed",
        "failedleaderelection",
        "failedscheduling",
        "leaderelection",
        "unhealthy",
    }
    RECOVERY_REASONS = {
        "leaderacquired",
        "leaderelection",
        "ready",
        "started",
        "healthy",
    }
    FAILURE_MARKERS = (
        "/readyz",
        "/livez",
        "/healthz",
        "connection refused",
        "context deadline exceeded",
        "dial tcp",
        "failed to renew lease",
        "failed to update lock",
        "health check failed",
        "i/o timeout",
        "leader election lost",
        "leaderelection lost",
        "leadership lost",
        "server was unable to return a response",
        "stopped leading",
        "the connection to the server",
        "tls handshake timeout",
        "unable to connect to the server",
    )
    RECOVERY_MARKERS = (
        "/readyz ok",
        "became leader",
        "became ready",
        "health check succeeded",
        "leader election acquired",
        "new leader elected",
        "readiness probe succeeded",
        "renewed lease",
        "successfully acquired lease",
    )
    API_MARKERS = (
        "kube-apiserver",
        "apiserver",
        "kubernetes.default.svc",
        "127.0.0.1:6443",
        "localhost:6443",
        "10.96.0.1:443",
        "6443",
    )

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

    def _component_for_event(self, event: dict[str, Any]) -> str | None:
        involved = event.get("involvedObject", {}) or {}
        text = " ".join(
            [
                self._source_component(event),
                str(involved.get("kind", "") if isinstance(involved, dict) else ""),
                str(involved.get("name", "") if isinstance(involved, dict) else ""),
                self._message_lower(event),
            ]
        )
        for component, markers in self.COMPONENT_MARKERS.items():
            if any(marker in text for marker in markers):
                return component
        return None

    def _transition_state(self, event: dict[str, Any]) -> str | None:
        reason = self._reason(event)
        message = self._message_lower(event)
        is_failure = reason in self.FAILURE_REASONS and any(
            marker in message for marker in self.FAILURE_MARKERS
        )
        if is_failure:
            return "degraded"

        is_recovery = reason in self.RECOVERY_REASONS and any(
            marker in message for marker in self.RECOVERY_MARKERS
        )
        if is_recovery:
            return "recovered"

        return None

    def _transitions(self, timeline: Timeline) -> list[dict[str, Any]]:
        transitions: list[dict[str, Any]] = []
        for event in self._ordered_recent(timeline):
            component = self._component_for_event(event)
            if component is None:
                continue
            state = self._transition_state(event)
            if state is None:
                continue
            transitions.append(
                {
                    "component": component,
                    "state": state,
                    "timestamp": self._event_ts(event),
                    "message": self._message(event),
                    "event": event,
                }
            )
        return transitions

    def _collapsed_sequence(self, transitions: list[dict[str, Any]]) -> list[str]:
        sequence: list[str] = []
        for transition in transitions:
            state = str(transition["state"])
            if not sequence or sequence[-1] != state:
                sequence.append(state)
        return sequence

    def _duration_seconds(self, transitions: list[dict[str, Any]]) -> int:
        timestamps: list[datetime] = []
        for transition in transitions:
            timestamp = transition.get("timestamp")
            if isinstance(timestamp, datetime):
                timestamps.append(timestamp)
        if len(timestamps) < 2:
            return 0
        return int((max(timestamps) - min(timestamps)).total_seconds())

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

    def _owner_ref(self, obj: dict[str, Any], kind: str) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
                return str(ref["name"])
        return None

    def _workload_symptom(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, str]:
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
                desired = int(
                    status.get(
                        "replicas",
                        deployment.get("spec", {}).get("replicas", 0),
                    )
                    or 0
                )
                available = int(status.get("availableReplicas", 0) or 0)
                updated = int(status.get("updatedReplicas", 0) or 0)
                if desired > 0 and (available < desired or updated < desired):
                    return {
                        "kind": "deployment",
                        "name": deployment_name,
                        "message": f"Deployment '{deployment_name}' intermittently stalls at {available}/{desired} available replicas while only {updated}/{desired} replicas are updated",
                    }

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        return {
            "kind": "pod",
            "name": pod_name,
            "message": f"Pod '{pod_name}' is exposed to intermittent control-plane availability while reconciliation flaps",
        }

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        transitions = self._transitions(timeline)
        if len(transitions) < self.MIN_TRANSITIONS:
            return None

        components = sorted({str(item["component"]) for item in transitions})
        if len(components) < self.MIN_COMPONENTS:
            return None

        failures = [item for item in transitions if item["state"] == "degraded"]
        recoveries = [item for item in transitions if item["state"] == "recovered"]
        if len(failures) < self.MIN_FAILURES or len(recoveries) < self.MIN_RECOVERIES:
            return None

        sequence = self._collapsed_sequence(transitions)
        if len(sequence) < 4:
            return None
        if not {"degraded", "recovered"}.issubset(sequence):
            return None
        for idx in range(1, min(len(sequence), 5)):
            if sequence[idx] == sequence[idx - 1]:
                return None

        duration = self._duration_seconds(transitions)
        if duration < self.MIN_DURATION_SECONDS:
            return None

        api_related = any(
            component == "apiserver"
            or any(
                marker in str(item["message"]).lower() for marker in self.API_MARKERS
            )
            for item in transitions
            for component in [item["component"]]
        )
        if not api_related:
            return None

        objects = context.get("objects", {}) or {}
        return {
            "transitions": transitions,
            "components": components,
            "sequence": sequence,
            "duration_seconds": duration,
            "failures": failures,
            "recoveries": recoveries,
            "api_service_ready": self._service_ready(objects, "kubernetes", "default"),
            "symptom": self._workload_symptom(pod, context),
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
            raise ValueError("ControlPlaneFlapping explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        components = [
            self.COMPONENT_DISPLAY.get(component, component)
            for component in candidate["components"]
        ]
        sequence_text = " -> ".join(candidate["sequence"])
        minutes = candidate["duration_seconds"] / 60.0
        symptom = candidate["symptom"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTROL_PLANE_TRANSITIONS_OBSERVED",
                    message=f"Timeline shows control-plane transitions: {sequence_text}",
                    role="temporal_context",
                ),
                Cause(
                    code="CONTROL_PLANE_FLAPPING",
                    message="Control-plane components repeatedly alternate between degraded and recovered states",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTROL_PLANE_CLIENTS_INTERMITTENTLY_LOSE_PROGRESS",
                    message="Controllers and scheduler intermittently lose API or lease progress during the flapping window",
                    role="controller_intermediate",
                ),
                Cause(
                    code="WORKLOAD_RECONCILIATION_INTERMITTENT",
                    message=symptom["message"],
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Control-plane state transitions observed: {sequence_text}",
            f"Components involved in flapping: {', '.join(components)}",
            f"Control-plane flapping persisted for {minutes:.1f} minutes across {len(candidate['transitions'])} transitions",
            symptom["message"],
        ]
        if candidate["api_service_ready"] is True:
            evidence.append(
                "Kubernetes service 'kubernetes' still has ready endpoints, which points to intermittent component or control-plane path flapping rather than a steady API Service outage"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [
                "The pod belongs to a workload whose reconciliation is exposed to control-plane flapping"
            ],
            f"{symptom['kind']}:{symptom['name']}": [symptom["message"]],
        }
        for component in candidate["components"]:
            display = self.COMPONENT_DISPLAY.get(component, component)
            messages = [
                str(item["message"])
                for item in candidate["transitions"]
                if item["component"] == component
            ]
            object_evidence[f"control-plane:{display}"] = messages[:4]

        if candidate["api_service_ready"] is True:
            object_evidence["service:kubernetes"] = [
                "Ready endpoints exist while control-plane components still alternate between failure and recovery"
            ]

        confidence = 0.9
        if len(candidate["components"]) >= 3:
            confidence = 0.94
        if candidate["api_service_ready"] is True:
            confidence = min(0.96, confidence + 0.01)

        return {
            "root_cause": "Control-plane availability is flapping, causing intermittent controller and scheduler progress",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Intermittent API server or etcd latency is causing leader-election renewals and health checks to alternate between failure and recovery",
                "Control-plane node network or host-resource pressure is briefly interrupting API access before recovering",
                "Load balancer or Service VIP instability is intermittently breaking control-plane client paths",
                "Control-plane static pods are repeatedly failing readiness probes and then recovering before a stable outage is established",
            ],
            "suggested_checks": [
                "kubectl get events -A --sort-by=.lastTimestamp",
                "kubectl get pods -n kube-system -l tier=control-plane -o wide",
                "kubectl get endpoints kubernetes -n default -o yaml",
                "kubectl get lease -n kube-system",
                "Compare kube-apiserver, kube-controller-manager, and kube-scheduler logs across the flapping window",
                f"kubectl describe pod {pod_name}",
            ],
        }
