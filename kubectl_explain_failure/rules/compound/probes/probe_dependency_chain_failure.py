from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProbeDependencyChainFailureRule(FailureRule):
    """
    Detects health checks that are coupled to an unavailable dependency, causing
    probe failures and downstream workload instability.

    Real-world behavior:
    - applications often wire `/readyz` or `/healthz` to deep dependency checks
      such as database or cache connectivity
    - when that dependency is unavailable, kubelet probe failures are only the
      downstream symptom; the real operational problem is the dependency chain
      coupled into health checks
    - this can leave the Pod NotReady or even trigger restart churn when the
      application exits after repeated failed dependency initialization
    """

    name = "ProbeDependencyChainFailure"
    category = "Compound"
    priority = 61
    deterministic = False

    phases = ["Pending", "Running", "CrashLoopBackOff"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    optional_objects = ["service", "endpoints", "endpointslice"]

    blocks = [
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "CrashLoopBackOff",
        "CrashLoopLivenessProbe",
        "ServiceEndpointsEmpty",
        "ProbeFailureEscalation",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
    ]

    WINDOW_MINUTES = 20
    MAX_DEP_TO_PROBE = timedelta(minutes=5)
    MAX_PROBE_TO_RESTART = timedelta(minutes=5)
    MAX_CHAIN_SPAN = timedelta(minutes=10)
    MIN_CHAIN_OCCURRENCES = 2

    DEPENDENCY_KEYWORDS = (
        "database",
        "db ",
        " db",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "mongodb",
        "mongo",
        "kafka",
        "rabbitmq",
        "dependency",
        "upstream",
    )

    DEPENDENCY_FAILURE_MARKERS = (
        "failed to connect",
        "connection refused",
        "connect: connection refused",
        "i/o timeout",
        "no such host",
        "server selection timeout",
        "dependency unavailable",
        "dependency is unavailable",
        "upstream unavailable",
        "dial tcp",
        "could not connect",
    )

    SERVICE_HOST_RE = re.compile(
        r"([a-z0-9-]+(?:\.[a-z0-9-]+){0,3}\.svc(?:\.cluster\.local)?(?::\d+)?)",
        re.IGNORECASE,
    )

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

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_start(event)
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

    def _candidate_container_names(self, pod: dict[str, Any]) -> list[str]:
        names = [
            str(status.get("name", ""))
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if status.get("name")
        ]
        if names:
            return names
        return [
            str(container.get("name", ""))
            for container in pod.get("spec", {}).get("containers", []) or []
            if container.get("name")
        ]

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

    def _extract_dependency_target(self, message: str) -> str | None:
        match = self.SERVICE_HOST_RE.search(message)
        if match:
            return match.group(1).lower()

        for keyword in self.DEPENDENCY_KEYWORDS:
            if keyword in message:
                return keyword.strip()
        return None

    def _service_name_from_target(self, target: str | None) -> str | None:
        if not target:
            return None
        if ".svc" in target:
            return target.split(".", 1)[0]
        if ":" in target and target.split(":", 1)[0]:
            return target.split(":", 1)[0]
        if target in {"database", "postgres", "postgresql", "mysql", "mariadb"}:
            return (
                "postgres"
                if target in {"database", "postgres", "postgresql"}
                else target
            )
        return None

    def _service_has_no_ready_endpoints(
        self,
        objects: dict[str, Any],
        service_name: str,
    ) -> bool:
        services = objects.get("service", {})
        endpoints = objects.get("endpoints", {})
        endpoint_slices = objects.get("endpointslice", {})

        if service_name not in services:
            return False

        if service_name in endpoints:
            ep = endpoints[service_name]
            subsets = ep.get("subsets", [])
            if not subsets:
                return True
            for subset in subsets:
                if subset.get("addresses"):
                    return False
            return True

        saw_slice = False
        for slice_obj in endpoint_slices.values():
            labels = slice_obj.get("metadata", {}).get("labels", {})
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            saw_slice = True
            endpoints_list = slice_obj.get("endpoints", [])
            if any(
                endpoint.get("conditions", {}).get("ready") is True
                for endpoint in endpoints_list
            ):
                return False
        return saw_slice

    def _is_dependency_failure_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> tuple[str | None, str | None]:
        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None, None

        message = self._event_message(event)
        has_keyword = any(keyword in message for keyword in self.DEPENDENCY_KEYWORDS)
        target = self._extract_dependency_target(message)
        has_failure = any(
            marker in message for marker in self.DEPENDENCY_FAILURE_MARKERS
        )
        if not has_failure:
            return None, None
        if not has_keyword and target is None:
            return None, None
        return target, message

    def _probe_kind_from_message(self, message: str) -> str | None:
        if "readiness probe" in message:
            return "readiness"
        if "liveness probe" in message:
            return "liveness"
        if "startup probe" in message:
            return "startup"
        return None

    def _is_probe_failure_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        dependency_target: str | None,
        assume_single_container: bool,
    ) -> str | None:
        component = self._event_component(event)
        if component and component != "kubelet":
            return None

        if self._event_reason(event) not in {"unhealthy", "failed"}:
            return None

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None

        message = self._event_message(event)
        probe_kind = self._probe_kind_from_message(message)
        if probe_kind is None or "fail" not in message:
            return None

        if dependency_target and dependency_target in message:
            return probe_kind

        dependency_markers = (
            "dependency unavailable",
            "dependency is unavailable",
            "database unavailable",
            "upstream unavailable",
            "because database",
            "because dependency",
            "because upstream",
        )
        if any(marker in message for marker in dependency_markers):
            return probe_kind

        return None

    def _is_restart_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        reason = self._event_reason(event)
        if reason not in {"backoff", "crashloopbackoff", "killing"}:
            return False

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False

        if reason == "killing":
            message = self._event_message(event)
            if "restart" not in message and "restarted" not in message:
                return False

        return True

    def _status_for_container(
        self, pod: dict[str, Any], container_name: str
    ) -> dict[str, Any]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if str(status.get("name", "")) == container_name:
                return status
        return {}

    def _best_candidate(
        self, pod: dict[str, Any], timeline: Timeline, context: dict[str, Any]
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        container_names = self._candidate_container_names(pod)
        if not container_names:
            return None

        assume_single_container = len(container_names) == 1
        objects = context.get("objects", {})
        best: dict[str, Any] | None = None

        for container_name in container_names:
            dependency_events: list[dict[str, Any]] = []
            for event in ordered:
                target, _msg = self._is_dependency_failure_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
                if target is not None:
                    dependency_events.append(
                        {
                            "event": event,
                            "target": target,
                        }
                    )

            if not dependency_events:
                continue

            status = self._status_for_container(pod, container_name)
            restart_count = int(status.get("restartCount", 0) or 0)
            current_state = status.get("state", {}) or {}
            ready = bool(status.get("ready", False))
            state_name = (
                "waiting"
                if "waiting" in current_state
                else (
                    "terminated"
                    if "terminated" in current_state
                    else "running" if "running" in current_state else "unknown"
                )
            )

            sequences: list[dict[str, Any]] = []
            for dep_item in dependency_events:
                dep_event = dep_item["event"]
                dep_target = dep_item["target"]
                dep_start = self._event_start(dep_event)
                dep_end = self._event_end(dep_event) or dep_start
                if dep_start is None or dep_end is None:
                    continue

                probe_match: dict[str, Any] | None = None
                for probe_event in ordered:
                    probe_start = self._event_start(probe_event)
                    if probe_start is None or probe_start < dep_start:
                        continue
                    if probe_start - dep_end > self.MAX_DEP_TO_PROBE:
                        break

                    probe_kind = self._is_probe_failure_event(
                        probe_event,
                        container_name=container_name,
                        dependency_target=dep_target,
                        assume_single_container=assume_single_container,
                    )
                    if probe_kind is None:
                        continue

                    probe_match = {
                        "event": probe_event,
                        "probe_kind": probe_kind,
                    }
                    break

                if probe_match is None:
                    continue

                probe_event = probe_match["event"]
                probe_start = self._event_start(probe_event)
                probe_end = self._event_end(probe_event) or probe_start
                if probe_start is None or probe_end is None:
                    continue

                restart_match: dict[str, Any] | None = None
                for restart_event in ordered:
                    restart_start = self._event_start(restart_event)
                    if restart_start is None or restart_start < probe_start:
                        continue
                    if restart_start - probe_end > self.MAX_PROBE_TO_RESTART:
                        break
                    if not self._is_restart_event(
                        restart_event,
                        container_name=container_name,
                        assume_single_container=assume_single_container,
                    ):
                        continue
                    restart_match = {"event": restart_event}
                    break

                if restart_match is None:
                    continue

                restart_event = restart_match["event"]
                restart_end = self._event_end(restart_event) or self._event_start(
                    restart_event
                )
                if restart_end is None:
                    continue
                if restart_end - dep_start > self.MAX_CHAIN_SPAN:
                    continue

                service_name = self._service_name_from_target(dep_target)
                service_empty = (
                    self._service_has_no_ready_endpoints(objects, service_name)
                    if service_name
                    else False
                )

                sequences.append(
                    {
                        "dependency_event": dep_event,
                        "probe_event": probe_event,
                        "restart_event": restart_event,
                        "probe_kind": probe_match["probe_kind"],
                        "dependency_target": dep_target,
                        "service_name": service_name,
                        "service_empty": service_empty,
                    }
                )

            if not sequences:
                continue

            if len(sequences) < self.MIN_CHAIN_OCCURRENCES and restart_count < 2:
                continue

            service_backed_sequences = sum(
                1 for seq in sequences if seq["service_empty"]
            )
            dominant_sequence = max(
                sequences,
                key=lambda seq: (
                    1 if seq["service_empty"] else 0,
                    self._occurrences(seq["probe_event"]),
                    self._occurrences(seq["restart_event"]),
                ),
            )

            candidate = {
                "container_name": container_name,
                "probe_kind": dominant_sequence["probe_kind"],
                "restart_count": restart_count,
                "ready": ready,
                "state_name": state_name,
                "sequence_count": len(sequences),
                "service_backed_sequences": service_backed_sequences,
                "dependency_target": dominant_sequence["dependency_target"],
                "service_name": dominant_sequence["service_name"],
                "service_empty": dominant_sequence["service_empty"],
                "dominant_dependency_message": str(
                    dominant_sequence["dependency_event"].get("message", "")
                ),
                "dominant_probe_message": str(
                    dominant_sequence["probe_event"].get("message", "")
                ),
                "dominant_restart_message": str(
                    dominant_sequence["restart_event"].get("message", "")
                ),
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["service_backed_sequences"],
                best["sequence_count"],
                best["restart_count"],
            )
            candidate_key = (
                candidate["service_backed_sequences"],
                candidate["sequence_count"],
                candidate["restart_count"],
            )
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline, context) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ProbeDependencyChainFailure requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "ProbeDependencyChainFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        probe_kind = candidate["probe_kind"]
        restart_count = candidate["restart_count"]
        ready = candidate["ready"]
        state_name = candidate["state_name"]
        sequence_count = candidate["sequence_count"]
        dependency_target = candidate["dependency_target"] or "dependency"
        service_name = candidate["service_name"]
        service_evidence = candidate["service_empty"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPENDENCY_OUTAGE_OBSERVED",
                    message=f"Recent failures show dependency '{dependency_target}' is unavailable before probe failures begin",
                    role="dependency_context",
                ),
                Cause(
                    code="HEALTH_CHECK_COUPLED_TO_DEPENDENCY",
                    message="Application health checks depend on external dependency availability instead of local process health",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="DEPENDENCY_FAILURE_PROPAGATES_TO_PROBES",
                    message=f"{probe_kind.capitalize()} probes fail as the dependency outage propagates through the health endpoint",
                    role="container_health_context",
                ),
                Cause(
                    code="WORKLOAD_ENTERS_RESTART_PRESSURE",
                    message="The pod becomes unstable or restarts as dependency-driven health failures accumulate",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Timeline shows dependency failure before {probe_kind} probe failures and restart pressure for container '{container_name}'",
            f"Observed {sequence_count} dependency -> probe failure -> restart chain(s) within the recent incident window",
            f"Container '{container_name}' now has restartCount={restart_count}, ready={ready}, state={state_name}",
        ]
        if service_evidence and service_name:
            evidence.append(
                f"Dependency service '{service_name}' has no ready endpoints, reinforcing the upstream outage signal"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                f"{probe_kind.capitalize()} health checks are failing downstream of dependency unavailability"
            ],
            f"container:{container_name}": [
                candidate["dominant_dependency_message"],
                candidate["dominant_probe_message"],
                candidate["dominant_restart_message"],
            ],
        }
        if service_evidence and service_name:
            object_evidence[f"service:{service_name}"] = [
                "Dependency service has no ready endpoints during the probe failure chain"
            ]

        return {
            "root_cause": "Health checks depend on an unavailable upstream dependency, causing probe failures and restart pressure",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The readiness or liveness endpoint is coupled to database or cache availability instead of local container health",
                "An upstream dependency outage is propagating into probe failures because the health check is too deep",
                "The application exits or degrades when the dependency is unavailable, turning an upstream outage into restart churn",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                "Inspect the health endpoint implementation and remove hard dependency checks from liveness where possible",
                "Verify dependency availability and service endpoints for the upstream database or backing service",
            ],
        }
