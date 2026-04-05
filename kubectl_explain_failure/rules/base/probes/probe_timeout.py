from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProbeTimeoutRule(FailureRule):
    """
    Detects kubelet probe checks that are timing out rather than failing due to
    an explicit bad status or exit code.

    Real-world behavior:
    - kubelet commonly reports timed-out probes as `Unhealthy` events whose
      messages include `context deadline exceeded`, `Client.Timeout exceeded`,
      `i/o timeout`, or another timeout marker
    - liveness/startup probe timeouts can trigger container restarts, while
      readiness probe timeouts keep the Pod running but NotReady
    - this rule is more specific than generic liveness/readiness/startup probe
      failure because it attributes the incident to timeout behavior rather than
      a generic failed check
    """

    name = "ProbeTimeout"
    category = "Container"
    priority = 24
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "LivenessProbeFailure",
        "ReadinessProbeFailure",
        "StartupProbeFailure",
    ]

    WINDOW_MINUTES = 15
    FAILURE_REASONS = {"unhealthy", "failed"}
    TIMEOUT_MARKERS = (
        "context deadline exceeded",
        "client.timeout exceeded",
        "client timeout exceeded",
        "i/o timeout",
        "timed out",
        "timeout exceeded",
        "deadlineexceeded",
        "rpc error: code = deadlineexceeded",
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
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

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
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _configured_probe_specs(
        self,
        pod: dict[str, Any],
    ) -> dict[str, dict[str, dict[str, Any]]]:
        configured: dict[str, dict[str, dict[str, Any]]] = {}
        for container in pod.get("spec", {}).get("containers", []) or []:
            name = str(container.get("name", "")).strip()
            if not name:
                continue

            probe_specs: dict[str, dict[str, Any]] = {}
            for probe_kind in ("liveness", "readiness", "startup"):
                probe_spec = container.get(f"{probe_kind}Probe")
                if probe_spec:
                    probe_specs[probe_kind] = probe_spec

            if probe_specs:
                configured[name] = probe_specs
        return configured

    def _container_status(
        self,
        pod: dict[str, Any],
        container_name: str,
    ) -> dict[str, Any] | None:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if str(status.get("name", "")).strip() == container_name:
                return status
        if len(statuses) == 1:
            return statuses[0]
        return None

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not container_name:
            return assume_single_container

        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if container_name.lower() in field_path:
                return True

        message = self._event_message(event)
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"failed container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True

        return assume_single_container and "container " not in message

    def _probe_kind_from_message(self, message: str) -> str | None:
        if "liveness probe" in message:
            return "liveness"
        if "readiness probe" in message:
            return "readiness"
        if "startup probe" in message:
            return "startup"
        return None

    def _is_timeout_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        allowed_probe_kinds: set[str],
        assume_single_container: bool,
    ) -> str | None:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None

        if self._event_reason(event) not in self.FAILURE_REASONS:
            return None

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None

        message = self._event_message(event)
        probe_kind = self._probe_kind_from_message(message)
        if probe_kind not in allowed_probe_kinds:
            return None

        if not any(marker in message for marker in self.TIMEOUT_MARKERS):
            return None

        return probe_kind

    def _is_restart_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        probe_kind: str,
        assume_single_container: bool,
    ) -> bool:
        component = self._event_component(event)
        if component and component != "kubelet":
            return False

        if self._event_reason(event) != "killing":
            return False

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False

        message = self._event_message(event)
        if f"{probe_kind} probe" not in message:
            return False
        if "restart" not in message and "restarted" not in message:
            return False

        return True

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        configured = self._configured_probe_specs(pod)
        if not configured:
            return None

        assume_single_container = len(configured) == 1
        best: dict[str, Any] | None = None

        for container_name, probe_specs in configured.items():
            status = self._container_status(pod, container_name) or {}
            current_state = status.get("state", {}) or {}
            last_state = status.get("lastState", {}) or {}
            ready = bool(status.get("ready", False))
            restart_count = int(status.get("restartCount", 0) or 0)

            state_name = (
                "waiting"
                if "waiting" in current_state
                else (
                    "terminated"
                    if "terminated" in current_state
                    else "running" if "running" in current_state else "unknown"
                )
            )

            allowed_probe_kinds = set(probe_specs.keys())
            timeout_events_by_kind: dict[str, list[dict[str, Any]]] = {
                kind: [] for kind in allowed_probe_kinds
            }

            for event in ordered:
                probe_kind = self._is_timeout_event(
                    event,
                    container_name=container_name,
                    allowed_probe_kinds=allowed_probe_kinds,
                    assume_single_container=assume_single_container,
                )
                if probe_kind is not None:
                    timeout_events_by_kind.setdefault(probe_kind, []).append(event)

            for probe_kind, timeout_events in timeout_events_by_kind.items():
                if not timeout_events:
                    continue

                restart_events = [
                    event
                    for event in ordered
                    if self._is_restart_event(
                        event,
                        container_name=container_name,
                        probe_kind=probe_kind,
                        assume_single_container=assume_single_container,
                    )
                ]

                if probe_kind == "readiness":
                    if ready:
                        continue
                else:
                    if (
                        restart_count < 1
                        and not restart_events
                        and "terminated" not in last_state
                    ):
                        continue

                timeout_occurrences = sum(
                    self._occurrences(event) for event in timeout_events
                )
                restart_signals = sum(
                    self._occurrences(event) for event in restart_events
                )
                probe_spec = probe_specs.get(probe_kind, {})
                timeout_seconds = probe_spec.get("timeoutSeconds")

                candidate = {
                    "container_name": container_name,
                    "probe_kind": probe_kind,
                    "timeout_occurrences": timeout_occurrences,
                    "restart_signals": restart_signals,
                    "restart_count": restart_count,
                    "ready": ready,
                    "state_name": state_name,
                    "timeout_seconds": timeout_seconds,
                    "dominant_timeout_message": max(
                        {str(event.get("message", "")) for event in timeout_events},
                        key=lambda message: sum(
                            self._occurrences(event)
                            for event in timeout_events
                            if str(event.get("message", "")) == message
                        ),
                    ),
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (
                    best["timeout_occurrences"],
                    best["restart_signals"],
                    best["restart_count"],
                )
                candidate_key = (
                    candidate["timeout_occurrences"],
                    candidate["restart_signals"],
                    candidate["restart_count"],
                )
                if candidate_key > best_key:
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ProbeTimeout requires a Timeline context")

        candidate = self._candidate(pod, timeline)
        if candidate is None:
            raise ValueError("ProbeTimeout explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        probe_kind = candidate["probe_kind"]
        timeout_occurrences = candidate["timeout_occurrences"]
        restart_signals = candidate["restart_signals"]
        restart_count = candidate["restart_count"]
        state_name = candidate["state_name"]
        ready = candidate["ready"]
        timeout_seconds = candidate["timeout_seconds"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="PROBE_CONFIGURED",
                    message=f"Container '{container_name}' has a {probe_kind} probe configured",
                    role="healthcheck_context",
                ),
                Cause(
                    code="PROBE_TIMED_OUT",
                    message=f"The {probe_kind} probe is timing out before the container responds",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="PROBE_TIMEOUT_IMPACT",
                    message=(
                        "Probe timeout is preventing the workload from becoming healthy or remaining stable"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Recent kubelet events show {probe_kind} probe timeout for container '{container_name}'",
            f"{probe_kind.capitalize()} probe timeout was observed {timeout_occurrences} time(s) within the last {self.WINDOW_MINUTES} minutes",
        ]
        if probe_kind == "readiness":
            evidence.append(
                f"Container '{container_name}' is still running but ready={ready}, consistent with readiness timeout behavior"
            )
        else:
            evidence.append(
                f"Container '{container_name}' has restartCount={restart_count} with state={state_name} after {probe_kind} timeout events"
            )
            if restart_signals:
                evidence.append(
                    f"Kubelet emitted {restart_signals} {probe_kind}-driven restart signal(s) after timeout events"
                )
        if timeout_seconds is not None:
            evidence.append(
                f"Configured {probe_kind}Probe.timeoutSeconds={timeout_seconds}"
            )

        return {
            "rule": self.name,
            "root_cause": f"Container {probe_kind}Probe is timing out",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"{probe_kind} probe timeout detected for a running container"
                ],
                f"container:{container_name}": [
                    candidate["dominant_timeout_message"],
                ],
            },
            "likely_causes": [
                "Probe timeoutSeconds is too low for the application's real response time",
                "The probe endpoint or exec command is waiting on a slow dependency or overloaded runtime path",
                "Node, network, or application latency is causing the health check to miss the kubelet timeout budget",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                f"Review {probe_kind}Probe.timeoutSeconds, periodSeconds, and failureThreshold",
                "Compare probe timeout timestamps with application and dependency latency",
            ],
        }
