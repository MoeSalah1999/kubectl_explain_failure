from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class LeaseObjectConflictRule(FailureRule):
    """
    Detects Kubernetes Lease coordination conflicts that disrupt leader election.

    Real-world behavior:
    - Controllers, schedulers, operators, and HA applications rely on Lease
      objects for coordinated leader election.
    - During API lag, stale caches, clock skew, rapid restarts, or split-brain
      conditions, clients frequently fail Lease updates with optimistic locking
      conflicts.
    - Brief conflicts are normal during leadership handoff, so this rule only
      matches sustained or repeated coordination failures.
    - A single transient "object has been modified" event should not trigger
      the rule.
    """

    name = "LeaseObjectConflict"
    category = "Compound"
    priority = 71
    deterministic = False
    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "lease",
            "deployment",
            "statefulset",
            "daemonset",
        ],
    }

    WINDOW_MINUTES = 20
    MIN_CONFLICT_EVENTS = 3
    SUSTAINED_CONFLICT_MINUTES = 5

    CACHE_KEY = "_lease_object_conflict_candidate"

    LEADER_COMPONENT_MARKERS = {
        "kube-controller-manager",
        "kube-scheduler",
        "controller-manager",
        "leader-election",
        "leader-elector",
        "operator",
    }

    CONFLICT_REASON_MARKERS = {
        "leadererelection",
        "failedleadererelection",
        "failedupdate",
        "leaseupdatefailed",
    }

    CONFLICT_MESSAGE_MARKERS = (
        "object has been modified",
        "the object has been modified",
        "please apply your changes to the latest version",
        "operation cannot be fulfilled on leases.coordination.k8s.io",
        "failed to update lock",
        "failed to acquire lease",
        "failed to renew lease",
        "optimistic lock",
        "resource version conflict",
        "leaderelection lost",
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

    def _is_lease_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}

        if not isinstance(involved, dict):
            return False

        kind = str(involved.get("kind", "")).lower()

        if kind != "lease":
            return False

        return True

    def _lease_name(self, event: dict[str, Any]) -> str:
        involved = event.get("involvedObject", {}) or {}

        if not isinstance(involved, dict):
            return "<unknown>"

        return str(involved.get("name", "<unknown>"))

    def _lease_namespace(self, event: dict[str, Any]) -> str:
        involved = event.get("involvedObject", {}) or {}

        if not isinstance(involved, dict):
            return "default"

        return str(involved.get("namespace", "default"))

    def _is_conflict_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        if not self._is_lease_event(event):
            return False

        reason = self._reason(event.get("reason"))
        message = self._message(event.get("message")).lower()
        component = self._source_component(event)

        if component and not any(
            marker in component for marker in self.LEADER_COMPONENT_MARKERS
        ):
            if "leader" not in message and "lease" not in message:
                return False

        if reason in self.CONFLICT_REASON_MARKERS:
            return True

        return any(marker in message for marker in self.CONFLICT_MESSAGE_MARKERS)

    def _recent_conflict_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if self._is_conflict_event(event):
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

        return max(0.0, (last_ts - first_ts).total_seconds() / 60.0)

    def _lease_holder_identity(
        self,
        lease_obj: dict[str, Any],
    ) -> str | None:
        spec = lease_obj.get("spec", {}) or {}

        holder = spec.get("holderIdentity")

        if holder:
            return str(holder)

        return None

    def _related_workload(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> str | None:
        namespace = self._namespace(pod)

        for owner in pod.get("metadata", {}).get("ownerReferences", []) or []:
            kind = str(owner.get("kind", ""))
            name = str(owner.get("name", ""))

            if kind and name:
                return f"{kind}/{name}"

        pod_name = pod.get("metadata", {}).get("name")

        if pod_name:
            return f"Pod/{pod_name}"

        return f"namespace/{namespace}"

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        recent_events = self._recent_conflict_events(timeline)

        if len(recent_events) < self.MIN_CONFLICT_EVENTS:
            return None

        span_minutes = self._event_span_minutes(recent_events)

        if span_minutes < self.SUSTAINED_CONFLICT_MINUTES and len(recent_events) < (
            self.MIN_CONFLICT_EVENTS + 2
        ):
            return None

        lease_counts: dict[tuple[str, str], int] = {}

        for event in recent_events:
            key = (
                self._lease_namespace(event),
                self._lease_name(event),
            )
            lease_counts[key] = lease_counts.get(key, 0) + 1

        dominant_lease = max(
            lease_counts.items(),
            key=lambda item: item[1],
        )

        lease_namespace, lease_name = dominant_lease[0]
        dominant_count = dominant_lease[1]

        lease_obj = (context.get("objects", {}).get("lease", {}).get(lease_name)) or {}

        holder_identity = None

        if isinstance(lease_obj, dict):
            if self._namespace(lease_obj) == lease_namespace:
                holder_identity = self._lease_holder_identity(lease_obj)

        latest_message = self._message(recent_events[-1].get("message"))

        return {
            "lease_name": lease_name,
            "lease_namespace": lease_namespace,
            "holder_identity": holder_identity,
            "recent_events": recent_events,
            "event_count": len(recent_events),
            "dominant_count": dominant_count,
            "span_minutes": span_minutes,
            "latest_message": latest_message,
            "related_workload": self._related_workload(pod, context),
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
            raise ValueError("LeaseObjectConflictRule explain() called without match")

        lease_name = candidate["lease_name"]
        lease_namespace = candidate["lease_namespace"]
        holder_identity = candidate.get("holder_identity")
        recent_events = candidate["recent_events"]
        latest_message = candidate["latest_message"]
        related_workload = candidate["related_workload"]

        evidence = [
            f"Lease '{lease_name}' in namespace '{lease_namespace}' generated repeated leader-election conflict errors",
            (
                f"{candidate['event_count']} Lease conflict events occurred "
                f"within the last {self.WINDOW_MINUTES} minutes"
            ),
            (
                f"Conflict activity persisted for approximately "
                f"{candidate['span_minutes']:.1f} minutes"
            ),
        ]

        object_evidence = {
            f"lease:{lease_name}": [
                "Repeated optimistic-lock or leader-election update conflicts detected"
            ]
        }

        if holder_identity:
            evidence.append(f"Current Lease holderIdentity is '{holder_identity}'")
            object_evidence[f"lease:{lease_name}"].append(
                f"holderIdentity={holder_identity}"
            )

        for event in recent_events:
            message = self._message(event.get("message"))

            if message and message not in object_evidence[f"lease:{lease_name}"]:
                object_evidence[f"lease:{lease_name}"].append(message)

        if latest_message:
            evidence.append(f"Latest Lease conflict message: {latest_message}")

        if related_workload:
            evidence.append(f"Affected workload context: {related_workload}")

        confidence = 0.91

        if (
            candidate["event_count"] >= 5
            and candidate["span_minutes"] >= self.SUSTAINED_CONFLICT_MINUTES
        ):
            confidence = 0.96

        elif candidate["event_count"] >= 4:
            confidence = 0.94

        chain = CausalChain(
            causes=[
                Cause(
                    code="LEASE_COORDINATION_ACTIVE",
                    message=(
                        f"Lease '{lease_name}' is being used for "
                        "leader election coordination"
                    ),
                    role="controller_context",
                ),
                Cause(
                    code="LEASE_OBJECT_CONFLICT",
                    message=(
                        "Leader-election updates are repeatedly failing "
                        "due to Lease object resourceVersion conflicts"
                    ),
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="LEADER_ELECTION_INSTABILITY",
                    message=(
                        "Controllers or HA components may repeatedly lose "
                        "or fail leadership renewal"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        ns_flag = f" -n {lease_namespace}" if lease_namespace else ""

        return {
            "root_cause": (
                f"Lease '{lease_name}' is experiencing repeated "
                "leader-election update conflicts"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Multiple controller instances are simultaneously attempting to update the same Lease object",
                "API server latency or stale informer caches are causing optimistic-lock update failures",
                "Leader-election participants are restarting rapidly and racing for Lease ownership",
                "Clock skew or delayed watch propagation is destabilizing Lease renewals",
                "High API server load is increasing coordination.k8s.io update contention",
            ],
            "suggested_checks": [
                f"kubectl describe lease {lease_name}{ns_flag}",
                (
                    "Inspect controller-manager, scheduler, operator, or "
                    "application logs for leader-election failures"
                ),
                (
                    "Check API server latency and etcd responsiveness during "
                    "the Lease conflict window"
                ),
                (
                    "Verify that only the expected number of HA replicas are "
                    "participating in leader election"
                ),
                (
                    "Inspect for crash loops or rapid restarts among "
                    "leader-election participants"
                ),
            ],
        }
