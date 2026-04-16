from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DependencyStartupOrderingFailureRule(FailureRule):
    """
    Detect startup sequences where an application exits because a required
    Service dependency is not ready yet, even though that dependency is healthy
    by the time we inspect the workload.

    Real-world behavior:
    - many applications try to open database or cache connections during process
      bootstrap and exit immediately if that dependency is not reachable
    - in Kubernetes, Deployment and Pod creation order does not guarantee
      dependency readiness order; readiness and retry logic must absorb that lag
    - when the dependency later becomes healthy but the application is still in
      restart pressure, the operational issue is usually startup coupling rather
      than a persistent Service outage
    """

    name = "DependencyStartupOrderingFailure"
    category = "Compound"
    priority = 62
    deterministic = False

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["service"],
        "optional_objects": ["endpoints", "endpointslice", "pod"],
    }

    blocks = [
        "CrashLoopBackOff",
        "RapidRestartEscalation",
    ]

    WINDOW_MINUTES = 20
    MAX_START_TO_DEPENDENCY = timedelta(minutes=2)
    MAX_DEPENDENCY_TO_RESTART = timedelta(minutes=2)
    MIN_SEQUENCE_OCCURRENCES = 2

    START_REASONS = {"Started", "Created"}
    RESTART_REASONS = {"BackOff", "Killing", "Failed"}
    DEPENDENCY_FAILURE_MARKERS = (
        "failed to connect",
        "dial tcp",
        "connect: connection refused",
        "connection refused",
        "i/o timeout",
        "context deadline exceeded",
        "timed out",
        "no route to host",
        "server selection timeout",
        "dependency unavailable",
        "upstream unavailable",
        "could not connect",
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

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", ""))

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", ""))

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

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
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if container_name.lower() in field_path:
                return True

        message = self._event_message(event).lower()
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"failed container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        return any(pattern in message for pattern in patterns) or (
            assume_single_container and "container " not in message
        )

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

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
    ) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        lowered = str(text or "").lower()
        for match in self.HOST_RE.finditer(lowered):
            host = str(match.group("host")).lower()
            if host not in aliases:
                continue
            port_text = match.group("port")
            port = None
            if isinstance(port_text, str) and port_text:
                try:
                    port = int(port_text)
                except Exception:
                    port = None
            refs.append(
                {
                    "service_name": aliases[host],
                    "host": host,
                    "port": port,
                    "text": text,
                }
            )
        return refs

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
                for ref in self._extract_service_refs_from_text(value, aliases):
                    refs.setdefault(ref["service_name"], []).append(
                        f"env {container_name}:{env.get('name', '<env>')}={value}"
                    )

            for field_name in ("command", "args"):
                for item in container.get(field_name, []) or []:
                    if not isinstance(item, str):
                        continue
                    for ref in self._extract_service_refs_from_text(item, aliases):
                        refs.setdefault(ref["service_name"], []).append(
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

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        for condition in pod_obj.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == "Ready":
                return condition.get("status") == "True"

        statuses = pod_obj.get("status", {}).get("containerStatuses", []) or []
        return bool(statuses) and all(bool(status.get("ready")) for status in statuses)

    def _service_ready_pods(
        self,
        objects: dict[str, Any],
        service: dict[str, Any],
    ) -> list[str]:
        selector = service.get("spec", {}).get("selector", {}) or {}
        if not selector:
            return []

        namespace = str(service.get("metadata", {}).get("namespace", "default"))
        ready_pods: list[str] = []

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
            if isinstance(pod_name, str) and pod_name:
                ready_pods.append(pod_name)

        return sorted(dict.fromkeys(ready_pods))

    def _current_dependency_state(
        self,
        objects: dict[str, Any],
        service_name: str,
    ) -> dict[str, Any] | None:
        service = objects.get("service", {}).get(service_name)
        if not isinstance(service, dict):
            return None

        namespace = str(service.get("metadata", {}).get("namespace", "default"))
        endpoint_addresses = self._service_ready_endpoints(
            objects, service_name, namespace
        )
        ready_pods = self._service_ready_pods(objects, service)

        return {
            "service_name": service_name,
            "namespace": namespace,
            "endpoint_addresses": endpoint_addresses,
            "ready_pods": ready_pods,
            "ready": bool(endpoint_addresses or ready_pods),
        }

    def _is_start_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        if self._event_reason(event) not in self.START_REASONS:
            return False
        component = self._event_component(event)
        if component and component != "kubelet":
            return False
        return self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        )

    def _dependency_failure_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
        aliases: dict[str, str],
    ) -> dict[str, Any] | None:
        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None

        message = self._event_message(event)
        lowered = message.lower()
        if "probe failed" in lowered or "readiness probe" in lowered:
            return None
        if not any(marker in lowered for marker in self.DEPENDENCY_FAILURE_MARKERS):
            return None

        refs = self._extract_service_refs_from_text(message, aliases)
        if not refs:
            return None

        return refs[0]

    def _is_restart_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        reason = self._event_reason(event)
        if reason not in self.RESTART_REASONS:
            return False

        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False

        if reason == "Killing":
            message = self._event_message(event).lower()
            if "restart" not in message and "restarted" not in message:
                return False
        if reason == "Failed" and "back-off" not in self._event_message(event).lower():
            return False
        return True

    def _status_for_container(
        self,
        pod: dict[str, Any],
        container_name: str,
    ) -> dict[str, Any]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if str(status.get("name", "")) == container_name:
                return status
        return {}

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        objects = context.get("objects", {})
        services = objects.get("service", {})
        if not services:
            return None

        namespace = str(pod.get("metadata", {}).get("namespace", "default")).lower()
        aliases = self._service_aliases(services, namespace)
        configured_refs = self._configured_refs(pod, aliases)

        container_names = self._candidate_container_names(pod)
        if not container_names:
            return None

        assume_single_container = len(container_names) == 1
        best: dict[str, Any] | None = None

        for container_name in container_names:
            status = self._status_for_container(pod, container_name)
            restart_count = int(status.get("restartCount", 0) or 0)
            ready = bool(status.get("ready", False))
            current_state = status.get("state", {}) or {}
            state_name = (
                "waiting"
                if "waiting" in current_state
                else (
                    "terminated"
                    if "terminated" in current_state
                    else "running" if "running" in current_state else "unknown"
                )
            )

            if ready and state_name == "running" and restart_count < 2:
                continue

            start_events = [
                event
                for event in ordered
                if self._is_start_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]
            if not start_events:
                continue

            sequences: list[dict[str, Any]] = []
            for start_event in start_events:
                start_ts = self._event_start(start_event)
                if start_ts is None:
                    continue

                dependency_match: dict[str, Any] | None = None
                for dep_event in ordered:
                    dep_ts = self._event_start(dep_event)
                    if dep_ts is None or dep_ts < start_ts:
                        continue
                    if dep_ts - start_ts > self.MAX_START_TO_DEPENDENCY:
                        break

                    dependency_ref = self._dependency_failure_event(
                        dep_event,
                        container_name=container_name,
                        assume_single_container=assume_single_container,
                        aliases=aliases,
                    )
                    if dependency_ref is None:
                        continue

                    dependency_state = self._current_dependency_state(
                        objects,
                        dependency_ref["service_name"],
                    )
                    if dependency_state is None or not dependency_state["ready"]:
                        continue

                    dependency_match = {
                        "event": dep_event,
                        "service_name": dependency_ref["service_name"],
                        "dependency_state": dependency_state,
                    }
                    break

                if dependency_match is None:
                    continue

                dep_event = dependency_match["event"]
                dep_ts = self._event_end(dep_event) or self._event_start(dep_event)
                if dep_ts is None:
                    continue

                restart_match: dict[str, Any] | None = None
                for restart_event in ordered:
                    restart_ts = self._event_start(restart_event)
                    if restart_ts is None or restart_ts < dep_ts:
                        continue
                    if restart_ts - dep_ts > self.MAX_DEPENDENCY_TO_RESTART:
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

                sequences.append(
                    {
                        "start_event": start_event,
                        "dependency_event": dep_event,
                        "restart_event": restart_match["event"],
                        "service_name": dependency_match["service_name"],
                        "dependency_state": dependency_match["dependency_state"],
                    }
                )

            if len(sequences) < self.MIN_SEQUENCE_OCCURRENCES and restart_count < 3:
                continue

            if not sequences:
                continue

            service_counts: dict[str, int] = {}
            for sequence in sequences:
                service_name = str(sequence["service_name"])
                service_counts[service_name] = service_counts.get(service_name, 0) + 1

            dominant_service = max(
                service_counts,
                key=lambda service_name: (
                    service_counts[service_name],
                    len(configured_refs.get(service_name, [])),
                    service_name,
                ),
            )
            dominant_sequence = next(
                sequence
                for sequence in sequences
                if sequence["service_name"] == dominant_service
            )

            current_ready = dominant_sequence["dependency_state"]
            candidate = {
                "container_name": container_name,
                "service_name": dominant_service,
                "sequence_count": service_counts[dominant_service],
                "restart_count": restart_count,
                "ready": ready,
                "state_name": state_name,
                "current_ready": current_ready,
                "config_sources": configured_refs.get(dominant_service, []),
                "start_message": self._event_message(dominant_sequence["start_event"]),
                "dependency_message": self._event_message(
                    dominant_sequence["dependency_event"]
                ),
                "restart_message": self._event_message(
                    dominant_sequence["restart_event"]
                ),
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["sequence_count"],
                len(best["config_sources"]),
                best["restart_count"],
            )
            candidate_key = (
                candidate["sequence_count"],
                len(candidate["config_sources"]),
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
            raise ValueError(
                "DependencyStartupOrderingFailure requires a Timeline context"
            )

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "DependencyStartupOrderingFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        service_name = candidate["service_name"]
        dependency_state = candidate["current_ready"]

        confidence = 0.94
        if candidate["config_sources"]:
            confidence += 0.01
        if dependency_state["endpoint_addresses"]:
            confidence += 0.01

        chain = CausalChain(
            causes=[
                Cause(
                    code="STARTUP_DEPENDENCY_REFERENCED",
                    message=(
                        f"Container '{container_name}' depends on Service '{service_name}' during process startup"
                    ),
                    role="configuration_context",
                ),
                Cause(
                    code="STARTUP_ORDERING_COUPLED_TO_DEPENDENCY",
                    message=(
                        f"Application startup exits when Service '{service_name}' is not ready yet instead of waiting or retrying"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="DEPENDENCY_FAILURE_HITS_BOOTSTRAP_PATH",
                    message=(
                        "Dependency connection failures happen immediately after container start, so bootstrap never reaches a stable running state"
                    ),
                    role="execution_intermediate",
                ),
                Cause(
                    code="RESTART_PRESSURE_PERSISTS_AFTER_DEPENDENCY_RECOVERS",
                    message=(
                        "Kubelet keeps restarting the workload even though the dependency is healthy by inspection time"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Timeline shows container '{container_name}' starting, then failing to connect to Service '{service_name}', then entering restart/backoff",
            f"Observed {candidate['sequence_count']} startup -> dependency failure -> restart chain(s) within the recent incident window",
            f"Container '{container_name}' is currently ready={candidate['ready']}, restartCount={candidate['restart_count']}, state={candidate['state_name']}",
            f"Service '{service_name}' currently has ready dependency backends, which makes a persistent outage less likely and points to startup ordering instead",
        ]
        if candidate["config_sources"]:
            evidence.append(
                "Workload configuration explicitly references the dependency Service during startup"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "The workload enters restart pressure because startup depends on immediate dependency availability"
            ],
            f"container:{container_name}": [
                candidate["dependency_message"],
                candidate["restart_message"],
            ],
            f"service:{service_name}": [],
        }
        if dependency_state["endpoint_addresses"]:
            object_evidence[f"service:{service_name}"].append(
                "Ready endpoint addresses now exist: "
                + ", ".join(dependency_state["endpoint_addresses"][:3])
            )
        if dependency_state["ready_pods"]:
            object_evidence[f"service:{service_name}"].append(
                "Selector currently resolves to ready pod(s): "
                + ", ".join(dependency_state["ready_pods"][:3])
            )
            for ready_pod in dependency_state["ready_pods"][:1]:
                object_evidence[f"pod:{ready_pod}"] = [
                    "Dependency pod is currently Ready, which suggests the startup failure happened before the backend stabilized"
                ]
        for source in candidate["config_sources"][:2]:
            object_evidence[f"pod:{pod_name}"].append(source)

        return {
            "root_cause": (
                f"Application startup is coupled to Service '{service_name}' readiness and fails before that dependency stabilizes"
            ),
            "confidence": min(0.97, confidence),
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The application exits on initial database or cache connection failure instead of retrying until the dependency is ready",
                "Startup sequencing assumes dependency pods are ready as soon as the app container starts, which Kubernetes does not guarantee",
                "Bootstrap logic performs hard dependency checks before the process can stay alive long enough for the dependency to recover",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                f"kubectl get endpoints {service_name}",
                "Add retry/backoff or explicit wait-for-dependency logic so startup tolerates dependency readiness lag",
            ],
        }
