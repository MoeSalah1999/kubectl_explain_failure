from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class EtcdLatencyHighRule(FailureRule):
    """
    Detects sustained etcd/API write latency impacting cluster behavior.

    Real-world behavior:
    - Slow etcd commits and API write latency commonly manifest as:
        * failed object updates
        * request timeouts
        * optimistic-lock conflicts
        * controller reconciliation lag
        * delayed pod scheduling/status propagation
    - Short spikes during leader elections or rolling updates are normal.
    - This rule requires repeated latency symptoms across a sustained window.
    - Kubernetes often surfaces etcd latency indirectly through kube-apiserver
      warnings/events rather than explicit "etcd is slow" messages.
    """

    name = "EtcdLatencyHigh"
    category = "APIMachinery"
    priority = 88
    deterministic = False

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "lease",
            "deployment",
            "statefulset",
            "daemonset",
        ],
    }

    WINDOW_MINUTES = 20
    MIN_LATENCY_EVENTS = 4
    MIN_SUSTAINED_MINUTES = 6

    CACHE_KEY = "_etcd_latency_high_candidate"

    API_COMPONENT_MARKERS = {
        "kube-apiserver",
        "apiserver",
        "kube-controller-manager",
        "kube-scheduler",
        "etcd",
    }

    LATENCY_REASON_MARKERS = {
        "failedupdate",
        "failedsync",
        "failedcreate",
        "timedout",
        "timeout",
        "leadererelection",
        "failedleadererelection",
        "node/statusupdatefailed",
    }

    LATENCY_MESSAGE_MARKERS = (
        "request timed out",
        "context deadline exceeded",
        "etcdserver: request timed out",
        "etcdserver: leader changed",
        "etcdserver: mvcc",
        "etcdserver: too many requests",
        "etcdserver: request timed out waiting for the applied index",
        "rpc error",
        "write latency",
        "apply request took too long",
        "waiting for etcd",
        "storage backend",
        "storagebackend",
        "failed to update lock",
        "resource version conflict",
        "object has been modified",
        "timeout while waiting for cache sync",
        "apiserver was unable to write",
        "unable to write event",
        "failed to persist",
        "client rate limiter wait returned an error",
        "watch chan error",
        "too old resource version",
        "leader election lost",
    )

    CONTROL_PLANE_NAMESPACES = {
        "kube-system",
        "openshift-etcd",
        "openshift-kube-apiserver",
        "openshift-kube-controller-manager",
    }

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None

        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _reason(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")

        if isinstance(source, dict):
            return str(source.get("component", "")).lower()

        return str(source or "").lower()

    def _event_namespace(self, event: dict[str, Any]) -> str:
        involved = event.get("involvedObject", {}) or {}

        if isinstance(involved, dict):
            return str(involved.get("namespace", "default"))

        return "default"

    def _involved_kind(self, event: dict[str, Any]) -> str:
        involved = event.get("involvedObject", {}) or {}

        if isinstance(involved, dict):
            return str(involved.get("kind", "")).lower()

        return ""

    def _is_control_plane_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        namespace = self._event_namespace(event)

        if namespace in self.CONTROL_PLANE_NAMESPACES:
            return True

        component = self._source_component(event)

        return any(marker in component for marker in self.API_COMPONENT_MARKERS)

    def _is_latency_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        reason = self._reason(event.get("reason"))
        message = self._message(event.get("message")).lower()

        if reason in self.LATENCY_REASON_MARKERS:
            return True

        if any(marker in message for marker in self.LATENCY_MESSAGE_MARKERS):
            return True

        component = self._source_component(event)

        if any(marker in component for marker in self.API_COMPONENT_MARKERS) and (
            "timeout" in message or "latency" in message or "etcd" in message
        ):
            return True

        return False

    def _recent_latency_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if not self._is_control_plane_event(event):
                continue

            if self._is_latency_event(event):
                results.append(event)

        results.sort(
            key=lambda event: self._event_ts(event)
            or datetime.min.replace(tzinfo=timezone.utc)
        )

        return results

    def _event_span_minutes(
        self,
        events: list[dict[str, Any]],
    ) -> float:
        if len(events) < 2:
            return 0.0

        first_ts = self._event_ts(events[0])
        last_ts = self._event_ts(events[-1])

        if first_ts is None or last_ts is None:
            return 0.0

        return max(
            0.0,
            (last_ts - first_ts).total_seconds() / 60.0,
        )

    def _kind_distribution(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, int]:
        distribution: dict[str, int] = {}

        for event in events:
            kind = self._involved_kind(event) or "unknown"

            distribution[kind] = distribution.get(kind, 0) + 1

        return distribution

    def _cross_component_signal(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        kinds = {
            self._involved_kind(event) for event in events if self._involved_kind(event)
        }

        return len(kinds) >= 2

    def _latest_message(
        self,
        events: list[dict[str, Any]],
    ) -> str:
        if not events:
            return ""

        return self._message(events[-1].get("message"))

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        recent_events = self._recent_latency_events(timeline)

        if len(recent_events) < self.MIN_LATENCY_EVENTS:
            return None

        span_minutes = self._event_span_minutes(recent_events)

        cross_component = self._cross_component_signal(recent_events)

        if span_minutes < self.MIN_SUSTAINED_MINUTES and not (
            len(recent_events) >= (self.MIN_LATENCY_EVENTS + 2)
        ):
            return None

        if not cross_component and len(recent_events) < 6:
            return None

        distribution = self._kind_distribution(recent_events)

        latest_message = self._latest_message(recent_events)

        dominant_kind = max(
            distribution.items(),
            key=lambda item: item[1],
        )[0]

        return {
            "recent_events": recent_events,
            "event_count": len(recent_events),
            "span_minutes": span_minutes,
            "cross_component": cross_component,
            "distribution": distribution,
            "dominant_kind": dominant_kind,
            "latest_message": latest_message,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(
            pod,
            context,
        )

        if candidate is None:
            raise ValueError("EtcdLatencyHighRule explain() called without match")

        recent_events = candidate["recent_events"]
        latest_message = candidate["latest_message"]

        evidence = [
            (
                f"{candidate['event_count']} API server / etcd latency-related "
                f"events occurred within the last "
                f"{self.WINDOW_MINUTES} minutes"
            ),
            (
                f"Latency symptoms persisted for approximately "
                f"{candidate['span_minutes']:.1f} minutes"
            ),
            (f"Most affected Kubernetes object type: " f"{candidate['dominant_kind']}"),
        ]

        if candidate["cross_component"]:
            evidence.append(
                "Latency symptoms affected multiple Kubernetes object types/components"
            )

        if latest_message:
            evidence.append(f"Latest latency-related message: {latest_message}")

        object_evidence: dict[str, list[str]] = {}

        for event in recent_events:
            involved = event.get("involvedObject", {}) or {}

            kind = str(involved.get("kind", "unknown")).lower()
            name = str(involved.get("name", "<unknown>"))

            key = f"{kind}:{name}"

            object_evidence.setdefault(key, [])

            message = self._message(event.get("message"))

            if message and message not in object_evidence[key]:
                object_evidence[key].append(message)

        confidence = 0.91

        if (
            candidate["event_count"] >= 7
            and candidate["cross_component"]
            and candidate["span_minutes"] >= self.MIN_SUSTAINED_MINUTES
        ):
            confidence = 0.97

        elif candidate["event_count"] >= 5 and candidate["cross_component"]:
            confidence = 0.95

        elif candidate["event_count"] >= 6:
            confidence = 0.94

        chain = CausalChain(
            causes=[
                Cause(
                    code="ETCD_BACKEND_UNDER_LOAD",
                    message=(
                        "The Kubernetes storage backend is exhibiting "
                        "elevated write or commit latency"
                    ),
                    role="infrastructure_context",
                ),
                Cause(
                    code="ETCD_LATENCY_HIGH",
                    message=(
                        "API writes and coordination operations are delayed "
                        "by slow etcd or API-server persistence behavior"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTROL_PLANE_RECONCILIATION_DELAYED",
                    message=(
                        "Controllers and workloads may experience delayed "
                        "state propagation, reconciliation, or scheduling"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                "Cluster control-plane operations are experiencing "
                "sustained etcd/API write latency"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "etcd disk I/O latency is slowing raft commit/apply operations",
                "API server write throughput is saturated under heavy cluster churn",
                "Large numbers of watches/events are overloading storage backend processing",
                "Control-plane nodes are CPU or memory constrained",
                "etcd quorum instability or network latency is delaying write acknowledgements",
                "Excessive object update frequency is creating storage contention",
            ],
            "suggested_checks": [
                "Inspect kube-apiserver logs for etcd request timeout or storage backend warnings",
                "Inspect etcd logs for slow apply, fsync, quorum, or leader instability warnings",
                "Check etcd disk latency and fsync performance on control-plane nodes",
                "Review API server request latency and inflight request saturation metrics",
                "Inspect cluster churn levels (rapid pod/controller/object updates)",
                "Verify control-plane node resource pressure and network health",
            ],
        }
