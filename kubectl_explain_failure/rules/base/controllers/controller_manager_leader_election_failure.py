from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ControllerManagerLeaderElectionFailureRule(FailureRule):
    """
    Detects a kube-controller-manager instance that cannot keep or renew its
    leader-election lease and is therefore becoming unhealthy.

    Real-world behavior:
    - transient "failed to acquire lease" noise on a healthy HA standby should
      not be enough on its own
    - repeated lease-renewal failures on the affected controller-manager pod,
      especially with restarts or readiness loss, are actionable
    - when kube-apiserver is clearly down, APIServerUnreachable should suppress
      this more local rule
    """

    name = "ControllerManagerLeaderElectionFailure"
    category = "Controller"
    priority = 60
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["service", "endpoints", "endpointslice"],
    }
    blocks = [
        "CrashLoopBackOff",
        "ControllerManagerUnavailable",
    ]

    WINDOW_MINUTES = 15
    MIN_TOTAL_OCCURRENCES = 2
    MIN_DURATION_SECONDS = 60
    CACHE_KEY = "_controller_manager_leader_election_failure_candidate"

    CONTROLLER_MANAGER_NAMES = (
        "kube-controller-manager",
        "controller-manager",
    )
    FAILURE_REASONS = {
        "leaderelection",
        "failedleaderelection",
        "failed",
    }
    BENIGN_MARKERS = (
        "successfully acquired lease",
        "became leader",
        "new leader elected",
        "attempting to acquire leader lease",
    )
    STRONG_FAILURE_MARKERS = (
        "failed to renew lease",
        "leaderelection lost",
        "leader election lost",
        "leadership lost",
        "stopped leading",
    )
    FAILURE_MARKERS = STRONG_FAILURE_MARKERS + (
        "failed to acquire lease",
        "error retrieving resource lock",
        "failed to update lock",
        "error initially creating leader election record",
    )
    API_ERROR_MARKERS = (
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "connection refused",
        "tls handshake timeout",
        "eof",
        "timeout",
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
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_ts(item[1]) is None else 0,
                    self._event_ts(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _pod_text(self, pod_obj: dict[str, Any]) -> str:
        metadata = pod_obj.get("metadata", {})
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

    def _is_controller_manager_pod(self, pod_obj: dict[str, Any]) -> bool:
        if pod_obj.get("metadata", {}).get("namespace") != "kube-system":
            return False
        text = self._pod_text(pod_obj)
        return any(marker in text for marker in self.CONTROLLER_MANAGER_NAMES)

    def _controller_manager_status(self, pod: dict[str, Any]) -> dict[str, Any] | None:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if not isinstance(status, dict):
                continue
            if "controller-manager" in str(status.get("name", "")).lower():
                return status
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

    def _is_degraded(self, status: dict[str, Any]) -> bool:
        state = status.get("state", {}) or {}
        waiting = state.get("waiting", {}) or {}
        terminated = state.get("terminated", {}) or {}
        return (
            not bool(status.get("ready", False))
            or waiting.get("reason") == "CrashLoopBackOff"
            or bool(terminated)
            or int(status.get("restartCount", 0) or 0) > 0
        )

    def _event_targets_pod(
        self, event: dict[str, Any], pod_obj: dict[str, Any]
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        if not isinstance(involved, dict):
            return False

        name = pod_obj.get("metadata", {}).get("name")
        namespace = pod_obj.get("metadata", {}).get("namespace")
        if involved.get("name") and involved.get("name") != name:
            return False
        if involved.get("namespace") and involved.get("namespace") != namespace:
            return False

        kind = str(involved.get("kind", "")).lower()
        return kind in {"", "pod"}

    def _occurrences(self, event: dict[str, Any]) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_strong_failure_message(self, message: str) -> bool:
        return any(marker in message for marker in self.STRONG_FAILURE_MARKERS)

    def _matches_failure_event(
        self, event: dict[str, Any], pod: dict[str, Any]
    ) -> bool:
        if not self._event_targets_pod(event, pod):
            return False

        if self._reason(event) not in self.FAILURE_REASONS:
            return False

        message = self._message(event)
        if not message or any(marker in message for marker in self.BENIGN_MARKERS):
            return False

        return any(marker in message for marker in self.FAILURE_MARKERS)

    def _event_rank(self, event: dict[str, Any]) -> tuple[int, int, int]:
        message = self._message(event)
        return (
            int(self._is_strong_failure_message(message)),
            int(any(marker in message for marker in self.API_ERROR_MARKERS)),
            self._occurrences(event),
        )

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
            metadata = obj.get("metadata", {})
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
        service_obj = self._find_named_object(
            objects, "service", service_name, namespace
        )
        if service_obj is None:
            return None

        endpoints = self._find_named_object(
            objects, "endpoints", service_name, namespace
        )
        if endpoints:
            for subset in endpoints.get("subsets", []) or []:
                if subset.get("addresses"):
                    return True
            return False

        for slice_obj in objects.get("endpointslice", {}).values():
            if not isinstance(slice_obj, dict):
                continue
            metadata = slice_obj.get("metadata", {})
            if metadata.get("namespace", "default") != namespace:
                continue
            labels = metadata.get("labels", {})
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            if any(
                endpoint.get("conditions", {}).get("ready") is True
                for endpoint in slice_obj.get("endpoints", []) or []
            ):
                return True
            return False

        return None

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not self._is_controller_manager_pod(pod):
            return None

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        status = self._controller_manager_status(pod)
        if status is None:
            return None

        ordered_events = self._ordered_recent(timeline)
        if not ordered_events:
            return None

        leader_events = [
            event for event in ordered_events if self._matches_failure_event(event, pod)
        ]
        if not leader_events:
            return None

        degraded = self._is_degraded(status)
        strong_events = [
            event
            for event in leader_events
            if self._is_strong_failure_message(self._message(event))
        ]
        total_occurrences = sum(self._occurrences(event) for event in leader_events)
        duration_seconds = int(
            timeline.duration_between(
                lambda event: self._matches_failure_event(event, pod)
            )
        )

        if not strong_events and not degraded:
            return None

        if (
            total_occurrences < self.MIN_TOTAL_OCCURRENCES
            and duration_seconds < self.MIN_DURATION_SECONDS
            and not degraded
        ):
            return None

        if not degraded and total_occurrences < 3 and duration_seconds < 180:
            return None

        representative = max(leader_events, key=self._event_rank)
        objects = context.get("objects", {})

        return {
            "pod_name": pod.get("metadata", {}).get("name", "<unknown>"),
            "container_name": status.get("name", "kube-controller-manager"),
            "state_name": self._container_state_name(status),
            "restart_count": int(status.get("restartCount", 0) or 0),
            "degraded": degraded,
            "strong_signal": bool(strong_events),
            "total_occurrences": total_occurrences,
            "duration_seconds": duration_seconds,
            "representative_message": str(representative.get("message", "")).strip(),
            "api_service_ready": self._service_ready(objects, "kubernetes", "default"),
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
                "ControllerManagerLeaderElectionFailure explain() called without match"
            )

        pod_name = candidate["pod_name"]
        container_name = candidate["container_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTROLLER_MANAGER_REQUIRES_LEASE_RENEWAL",
                    message="kube-controller-manager must keep renewing its coordination lease to remain the active controller leader",
                    role="controller_context",
                ),
                Cause(
                    code="CONTROLLER_MANAGER_LEADER_ELECTION_FAILURE",
                    message="kube-controller-manager cannot renew or hold its leader-election lease",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTROLLER_MANAGER_POD_UNHEALTHY",
                    message="The controller-manager pod becomes unhealthy or restarts after losing leadership",
                    role="component_symptom",
                ),
            ]
        )

        evidence = [
            f"Recent leader-election failures target kube-controller-manager pod '{pod_name}' with container '{container_name}' state={candidate['state_name']} restartCount={candidate['restart_count']}",
            f"Leader-election failures repeat {candidate['total_occurrences']} times over {candidate['duration_seconds']}s within the recent incident window",
            f"Representative leader-election signal: {candidate['representative_message']}",
        ]
        if candidate["api_service_ready"] is True:
            evidence.append(
                "Kubernetes service 'kubernetes' still has ready API endpoints, which localizes the failure to this controller-manager instance or its path to the API"
            )

        object_evidence = {
            f"pod:{pod_name}": [candidate["representative_message"]],
        }
        if candidate["api_service_ready"] is True:
            object_evidence["service:kubernetes"] = [
                "The kubernetes Service still has ready endpoints during the controller-manager lease-renewal failure"
            ]

        confidence = 0.95
        if candidate["strong_signal"] and candidate["degraded"]:
            confidence = 0.96
        if candidate["total_occurrences"] >= 4 or candidate["duration_seconds"] >= 180:
            confidence = 0.97
        if candidate["api_service_ready"] is True:
            confidence = min(0.98, confidence + 0.01)

        return {
            "root_cause": "kube-controller-manager cannot maintain its leader-election lease, so the controller-manager pod becomes unhealthy",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Intermittent connectivity, packet loss, or timeouts between kube-controller-manager and the Kubernetes API endpoint are breaking lease renewals",
                "Clock skew or long host stalls are causing lease deadlines to be missed",
                "Coordination Lease updates are failing because of RBAC, coordination API, or etcd-side errors",
                "The kube-controller-manager process is unstable and restarts after losing leadership",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n kube-system",
                f"kubectl logs -n kube-system {pod_name} -c {container_name}",
                "kubectl get lease kube-controller-manager -n kube-system -o yaml",
                "Verify control-plane clock sync and the controller-manager path to the Kubernetes API VIP",
            ],
        }
