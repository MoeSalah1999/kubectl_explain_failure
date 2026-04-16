from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class Candidate(TypedDict):
    container_name: str
    service_name: str
    dependency_pod_name: str
    dependency_ready_at: datetime
    pod_ready_at: datetime
    recovery_delay_seconds: float
    dependency_failure_count: int
    post_recovery_probe_failure_count: int
    config_sources: list[str]
    ready_endpoints: list[str]
    representative_dependency_failure: str
    representative_post_recovery_failure: str


class DependencyRecoveryDelayRule(FailureRule):
    """
    Detect a workload whose dependency recovers first, but whose own readiness
    recovers only after a materially delayed gap.

    Real-world behavior:
    - applications often expose readiness that depends on a database, cache, or
      internal service becoming reachable
    - the upstream Service can recover first, yet the dependent workload may
      stay NotReady for several more minutes while connection pools, retries,
      caches, or circuit breakers recover
    - this points to dependency-coupled recovery behavior rather than a still-
      active upstream outage
    """

    name = "DependencyRecoveryDelay"
    category = "Temporal"
    priority = 66
    deterministic = False

    phases = ["Running"]
    container_states = ["running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["service"],
        "optional_objects": ["pod", "endpoints", "endpointslice"],
    }

    blocks = [
        "ReadinessProbeFailure",
    ]

    WINDOW_MINUTES = 30
    MIN_DELAY = timedelta(minutes=5)
    MIN_TOTAL_FAILURE_OCCURRENCES = 3
    MIN_POST_RECOVERY_FAILURE_OCCURRENCES = 1

    DEPENDENCY_FAILURE_MARKERS = (
        "failed to connect",
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "timed out",
        "server selection timeout",
        "dependency unavailable",
        "dependency is unavailable",
        "upstream unavailable",
        "database unavailable",
        "could not connect",
    )
    DEPENDENCY_KEYWORDS = (
        "database",
        "db",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "cache",
        "upstream",
        "dependency",
    )
    READINESS_FAILURE_MARKERS = (
        "readiness probe failed",
        "probe failed",
        "not ready",
        "returned 503",
        "statuscode: 503",
        "http probe failed",
    )
    HOST_RE = re.compile(
        r"(?:(?:https?|tcp|postgres(?:ql)?|mysql|redis|amqp)://)?"
        r"(?P<host>[a-z0-9-]+(?:\.[a-z0-9-]+){0,4})"
        r"(?::(?P<port>\d{1,5}))?",
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

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", ""))

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _container_names(self, pod: dict[str, Any]) -> list[str]:
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
        lowered = container_name.lower()
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path and lowered in field_path:
                return True

        message = self._event_message(event).lower()
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"containers{{{lowered}}}",
        )
        return any(pattern in message for pattern in patterns) or (
            assume_single_container and "container " not in message
        )

    def _pod_ready_transition(self, pod_obj: dict[str, Any]) -> datetime | None:
        conditions = pod_obj.get("status", {}).get("conditions", []) or []
        for condition in conditions:
            if condition.get("type") != "Ready":
                continue
            if condition.get("status") != "True":
                continue
            ready_at = self._parse_timestamp(condition.get("lastTransitionTime"))
            if ready_at is not None:
                return ready_at
        return None

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        for condition in pod_obj.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == "Ready":
                return condition.get("status") == "True"

        statuses = pod_obj.get("status", {}).get("containerStatuses", []) or []
        return bool(statuses) and all(bool(status.get("ready")) for status in statuses)

    def _service_aliases(
        self,
        services: dict[str, Any],
        namespace: str,
    ) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for service_name in services:
            normalized = str(service_name).lower()
            aliases[normalized] = service_name
            aliases[f"{normalized}.{namespace}"] = service_name
            aliases[f"{normalized}.{namespace}.svc"] = service_name
            aliases[f"{normalized}.{namespace}.svc.cluster.local"] = service_name
        return aliases

    def _extract_service_refs_from_text(
        self,
        text: str,
        aliases: dict[str, str],
    ) -> list[str]:
        refs: list[str] = []
        lowered = str(text or "").lower()
        for match in self.HOST_RE.finditer(lowered):
            host = str(match.group("host")).lower()
            if host not in aliases:
                continue
            refs.append(aliases[host])
        return list(dict.fromkeys(refs))

    def _configured_refs(
        self,
        pod: dict[str, Any],
        aliases: dict[str, str],
    ) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}

        for container in pod.get("spec", {}).get("containers", []) or []:
            container_name = str(container.get("name", "")).strip() or "<unknown>"

            for env in container.get("env", []) or []:
                value = env.get("value")
                if not isinstance(value, str):
                    continue
                for service_name in self._extract_service_refs_from_text(
                    value, aliases
                ):
                    refs.setdefault(service_name, []).append(
                        f"env {container_name}:{env.get('name', '<env>')}={value}"
                    )

            for field_name in ("command", "args"):
                for item in container.get(field_name, []) or []:
                    if not isinstance(item, str):
                        continue
                    for service_name in self._extract_service_refs_from_text(
                        item, aliases
                    ):
                        refs.setdefault(service_name, []).append(
                            f"{field_name} {container_name}:{item}"
                        )

        return {
            service_name: list(dict.fromkeys(sources))
            for service_name, sources in refs.items()
        }

    def _service_ready_endpoints(
        self,
        objects: dict[str, Any],
        service_name: str,
        namespace: str,
    ) -> list[str]:
        addresses: list[str] = []

        endpoint = objects.get("endpoints", {}).get(service_name)
        if isinstance(endpoint, dict):
            metadata = endpoint.get("metadata", {}) or {}
            if metadata.get("namespace", namespace) == namespace:
                for subset in endpoint.get("subsets", []) or []:
                    for address in subset.get("addresses", []) or []:
                        ip = address.get("ip")
                        if isinstance(ip, str) and ip:
                            addresses.append(ip)

        for slice_obj in objects.get("endpointslice", {}).values():
            if not isinstance(slice_obj, dict):
                continue
            metadata = slice_obj.get("metadata", {}) or {}
            if metadata.get("namespace", namespace) != namespace:
                continue
            labels = metadata.get("labels", {}) or {}
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            for endpoint_obj in slice_obj.get("endpoints", []) or []:
                if endpoint_obj.get("conditions", {}).get("ready") is not True:
                    continue
                for address in endpoint_obj.get("addresses", []) or []:
                    if isinstance(address, str) and address:
                        addresses.append(address)

        return list(dict.fromkeys(addresses))

    def _service_ready_pods(
        self,
        objects: dict[str, Any],
        service: dict[str, Any],
    ) -> list[tuple[str, datetime]]:
        selector = service.get("spec", {}).get("selector", {}) or {}
        if not selector:
            return []

        namespace = str(service.get("metadata", {}).get("namespace", "default"))
        ready_pods: list[tuple[str, datetime]] = []

        for pod_obj in objects.get("pod", {}).values():
            if not isinstance(pod_obj, dict):
                continue
            metadata = pod_obj.get("metadata", {}) or {}
            if metadata.get("namespace", "default") != namespace:
                continue
            labels = metadata.get("labels", {}) or {}
            if any(labels.get(key) != value for key, value in selector.items()):
                continue
            if not self._pod_ready(pod_obj):
                continue
            pod_name = metadata.get("name")
            ready_at = self._pod_ready_transition(pod_obj)
            if not isinstance(pod_name, str) or not pod_name or ready_at is None:
                continue
            ready_pods.append((pod_name, ready_at))

        return sorted(ready_pods, key=lambda item: item[1])

    def _message_service_refs(
        self,
        message: str,
        aliases: dict[str, str],
        configured_services: list[str],
    ) -> list[str]:
        refs = self._extract_service_refs_from_text(message, aliases)
        if refs:
            return refs

        lowered = message.lower()
        if len(configured_services) == 1 and any(
            keyword in lowered for keyword in self.DEPENDENCY_KEYWORDS
        ):
            return configured_services

        return []

    def _dependency_failure_events(
        self,
        ordered: list[dict[str, Any]],
        *,
        container_name: str,
        aliases: dict[str, str],
        configured_services: list[str],
        assume_single_container: bool,
    ) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []

        for event in ordered:
            if not self._container_event_match(
                event,
                container_name,
                assume_single_container=assume_single_container,
            ):
                continue

            message = self._event_message(event)
            lowered = message.lower()
            if not any(marker in lowered for marker in self.DEPENDENCY_FAILURE_MARKERS):
                continue

            for service_name in self._message_service_refs(
                message,
                aliases,
                configured_services,
            ):
                matched.append(
                    {
                        "event": event,
                        "service_name": service_name,
                        "message": message,
                    }
                )

        return matched

    def _event_overlaps_window(
        self,
        event: dict[str, Any],
        *,
        start: datetime,
        end: datetime,
    ) -> bool:
        event_start = self._event_start(event)
        event_end = self._event_end(event) or event_start
        if event_start is None or event_end is None:
            return False
        return event_start <= end and event_end >= start

    def _post_recovery_probe_failures(
        self,
        ordered: list[dict[str, Any]],
        *,
        container_name: str,
        dependency_ready_at: datetime,
        pod_ready_at: datetime,
        assume_single_container: bool,
    ) -> list[dict[str, Any]]:
        failures: list[dict[str, Any]] = []

        for event in ordered:
            if not self._container_event_match(
                event,
                container_name,
                assume_single_container=assume_single_container,
            ):
                continue

            message = self._event_message(event).lower()
            if not any(marker in message for marker in self.READINESS_FAILURE_MARKERS):
                continue
            if self._event_reason(event) not in {"unhealthy", "failed"}:
                continue
            if not self._event_overlaps_window(
                event,
                start=dependency_ready_at,
                end=pod_ready_at,
            ):
                continue

            failures.append(event)

        return failures

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> Candidate | None:
        objects = context.get("objects", {})
        services = objects.get("service", {})
        if not services:
            return None

        pod_ready_at = self._pod_ready_transition(pod)
        if pod_ready_at is None or not self._pod_ready(pod):
            return None

        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        namespace = str(pod.get("metadata", {}).get("namespace", "default")).lower()
        aliases = self._service_aliases(services, namespace)
        configured_refs = self._configured_refs(pod, aliases)

        container_names = self._container_names(pod)
        if not container_names:
            return None

        assume_single_container = len(container_names) == 1
        best: Candidate | None = None

        for container_name in container_names:
            configured_services = sorted(configured_refs.keys())
            dependency_failures = self._dependency_failure_events(
                ordered,
                container_name=container_name,
                aliases=aliases,
                configured_services=configured_services,
                assume_single_container=assume_single_container,
            )
            if not dependency_failures:
                continue

            failures_by_service: dict[str, list[dict[str, Any]]] = {}
            for item in dependency_failures:
                failures_by_service.setdefault(item["service_name"], []).append(item)

            for service_name, service_failures in failures_by_service.items():
                service_obj = services.get(service_name)
                if not isinstance(service_obj, dict):
                    continue

                service_namespace = str(
                    service_obj.get("metadata", {}).get("namespace", "default")
                )
                ready_pods = self._service_ready_pods(objects, service_obj)
                ready_endpoints = self._service_ready_endpoints(
                    objects,
                    service_name,
                    service_namespace,
                )
                if not ready_pods and not ready_endpoints:
                    continue

                failure_starts: list[datetime] = []
                for item in service_failures:
                    event_start = self._event_start(item["event"])
                    if event_start is not None:
                        failure_starts.append(event_start)

                if not failure_starts:
                    continue
                first_failure_start = min(failure_starts)

                dependency_ready: tuple[str, datetime] | None = None
                for dependency_pod_name, ready_at in ready_pods:
                    if ready_at < first_failure_start:
                        continue
                    if ready_at >= pod_ready_at:
                        continue
                    dependency_ready = (dependency_pod_name, ready_at)
                    break

                if dependency_ready is None:
                    continue

                dependency_pod_name, dependency_ready_at = dependency_ready
                recovery_delay = pod_ready_at - dependency_ready_at
                if recovery_delay < self.MIN_DELAY:
                    continue

                post_recovery_probe_failures = self._post_recovery_probe_failures(
                    ordered,
                    container_name=container_name,
                    dependency_ready_at=dependency_ready_at,
                    pod_ready_at=pod_ready_at,
                    assume_single_container=assume_single_container,
                )
                post_recovery_failure_count = sum(
                    self._occurrences(event) for event in post_recovery_probe_failures
                )
                if (
                    post_recovery_failure_count
                    < self.MIN_POST_RECOVERY_FAILURE_OCCURRENCES
                ):
                    continue

                dependency_failure_count = sum(
                    self._occurrences(item["event"]) for item in service_failures
                )
                if (
                    dependency_failure_count + post_recovery_failure_count
                    < self.MIN_TOTAL_FAILURE_OCCURRENCES
                ):
                    continue

                candidate: Candidate = {
                    "container_name": container_name,
                    "service_name": service_name,
                    "dependency_pod_name": dependency_pod_name,
                    "dependency_ready_at": dependency_ready_at,
                    "pod_ready_at": pod_ready_at,
                    "recovery_delay_seconds": recovery_delay.total_seconds(),
                    "dependency_failure_count": dependency_failure_count,
                    "post_recovery_probe_failure_count": post_recovery_failure_count,
                    "config_sources": configured_refs.get(service_name, []),
                    "ready_endpoints": ready_endpoints,
                    "representative_dependency_failure": service_failures[0]["message"],
                    "representative_post_recovery_failure": self._event_message(
                        post_recovery_probe_failures[0]
                    ),
                }

                if best is None:
                    best = candidate
                    continue

                best_key = (
                    best["recovery_delay_seconds"],
                    best["post_recovery_probe_failure_count"],
                    best["dependency_failure_count"],
                    len(best["config_sources"]),
                )
                candidate_key = (
                    candidate["recovery_delay_seconds"],
                    candidate["post_recovery_probe_failure_count"],
                    candidate["dependency_failure_count"],
                    len(candidate["config_sources"]),
                )
                if candidate_key > best_key:
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("DependencyRecoveryDelay requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("DependencyRecoveryDelay explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        service_name = candidate["service_name"]
        dependency_pod_name = candidate["dependency_pod_name"]
        dependency_ready_at = candidate["dependency_ready_at"].isoformat()
        pod_ready_at = candidate["pod_ready_at"].isoformat()
        recovery_delay_minutes = candidate["recovery_delay_seconds"] / 60.0

        confidence = 0.92
        if candidate["config_sources"]:
            confidence += 0.02
        if candidate["post_recovery_probe_failure_count"] >= 2:
            confidence += 0.01
        if candidate["ready_endpoints"]:
            confidence += 0.01

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_DEPENDENCY_CONFIGURED",
                    message=(
                        f"Container '{container_name}' is configured to depend on Service '{service_name}'"
                    ),
                    role="configuration_context",
                ),
                Cause(
                    code="DEPENDENCY_RECOVERED_BEFORE_WORKLOAD",
                    message=(
                        f"Service '{service_name}' recovered before the workload became Ready"
                    ),
                    role="temporal_context",
                ),
                Cause(
                    code="DEPENDENCY_COUPLED_RECOVERY_PATH",
                    message=(
                        "Workload readiness remained degraded after dependency recovery, indicating reconnect or health-check recovery is tightly coupled to the upstream service"
                    ),
                    role="configuration_root",
                    blocking=False,
                ),
                Cause(
                    code="WORKLOAD_RECOVERY_DELAYED",
                    message="The pod recovered only after a prolonged lag following dependency restoration",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Container '{container_name}' references Service '{service_name}' in workload configuration",
            f"Dependency pod '{dependency_pod_name}' for Service '{service_name}' became Ready at {dependency_ready_at}",
            f"Readiness failures for container '{container_name}' continued after dependency recovery until the pod became Ready at {pod_ready_at}",
            f"Workload recovery lag after dependency recovery was {recovery_delay_minutes:.1f} minutes",
            f"Observed {candidate['dependency_failure_count']} dependency-related failure occurrence(s) and {candidate['post_recovery_probe_failure_count']} post-recovery readiness failure occurrence(s) in the incident window",
        ]

        object_evidence = {
            f"pod:{pod_name}": [
                f"Pod Ready transition happened {recovery_delay_minutes:.1f} minutes after Service '{service_name}' recovered"
            ],
            f"container:{container_name}": [
                candidate["representative_dependency_failure"],
                candidate["representative_post_recovery_failure"],
            ],
            f"service:{service_name}": [
                f"Service currently has ready backends after dependency pod '{dependency_pod_name}' recovered at {dependency_ready_at}"
            ],
            f"pod:{dependency_pod_name}": [
                f"Dependency pod became Ready before the dependent workload recovered ({dependency_ready_at} -> {pod_ready_at})"
            ],
        }
        if candidate["ready_endpoints"]:
            object_evidence[f"service:{service_name}"].append(
                "Ready endpoint addresses now exist: "
                + ", ".join(candidate["ready_endpoints"][:3])
            )
        for source in candidate["config_sources"][:2]:
            object_evidence[f"pod:{pod_name}"].append(source)

        return {
            "root_cause": (
                f"Workload readiness recovered {recovery_delay_minutes:.1f} minutes after Service '{service_name}' recovered, indicating dependency-coupled recovery delay"
            ),
            "confidence": min(0.96, confidence),
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Application readiness depends too directly on upstream dependency health instead of degrading gracefully while reconnecting",
                "Connection pools, retry backoff, or circuit-breaker state delayed recovery after the dependency itself was already healthy",
                "Health checks keep reporting NotReady until downstream sessions are rebuilt, which prolongs recovery after service restoration",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get endpoints {service_name}",
                f"kubectl logs {pod_name} -c {container_name} --since=30m",
                "Review readiness endpoint behavior, reconnect backoff, and dependency retry settings so recovery tracks upstream restoration more closely",
            ],
        }
