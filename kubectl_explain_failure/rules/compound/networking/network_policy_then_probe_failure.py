from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class TargetInfo(TypedDict):
    raw: str
    host: str
    port: int | None
    service_name: str | None
    service_namespace: str


class SequenceInfo(TypedDict):
    dependency_event: dict[str, Any]
    probe_event: dict[str, Any]
    probe_kind: str
    strength: int
    target: TargetInfo
    service_ready: bool


class CandidateInfo(TypedDict):
    container_name: str
    probe_kind: str
    ready: bool
    restart_count: int
    state_name: str
    sequence_count: int
    total_strength: int
    target: TargetInfo
    service_ready: bool
    policy_names: list[str]
    dependency_message: str
    probe_message: str


class NetworkPolicyThenProbeFailureRule(FailureRule):
    name = "NetworkPolicyThenProbeFailure"
    category = "Compound"
    priority = 64
    deterministic = False
    phases = ["Running", "CrashLoopBackOff"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["networkpolicy"],
        "optional_objects": ["service", "endpoints", "endpointslice", "namespace"],
    }
    blocks = [
        "NetworkPolicyBlocked",
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
        "ProbeDependencyChainFailure",
    ]

    WINDOW_MINUTES = 20
    MAX_DEP_TO_PROBE = timedelta(minutes=4)
    MIN_SEQUENCE_OCCURRENCES = 2

    PROBE_COUPLING_MARKERS = (
        "dependency",
        "upstream",
        "database",
        "db ",
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "mongodb",
        "mongo",
        "kafka",
        "rabbitmq",
        "timed out",
        "timeout",
        "connection refused",
        "unavailable",
    )
    CONNECTIVITY_FAILURE_MARKERS = (
        "failed to connect",
        "dial tcp",
        "connect: connection refused",
        "connection refused",
        "i/o timeout",
        "connection timed out",
        "no route to host",
        "network is unreachable",
        "operation timed out",
    )
    DNS_FAILURE_MARKERS = (
        "no such host",
        "server misbehaving",
        "temporary failure in name resolution",
        "lookup ",
    )
    TARGET_RE = re.compile(r"(?P<host>[a-z0-9.-]+)(?::(?P<port>\d+))?", re.IGNORECASE)

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

        message = self._event_message(event)
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"failed container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        return any(p in message for p in patterns) or (
            assume_single_container and "container " not in message
        )

    def _match_selector(
        self,
        selector: dict[str, Any] | None,
        labels: dict[str, str],
    ) -> bool:
        if selector is None:
            return False
        if not selector:
            return True

        for key, expected in (selector.get("matchLabels", {}) or {}).items():
            if labels.get(key) != expected:
                return False

        for expr in selector.get("matchExpressions", []) or []:
            key = expr.get("key")
            operator = expr.get("operator")
            values = expr.get("values", []) or []
            actual = labels.get(key)
            if operator == "In" and actual not in values:
                return False
            if operator == "NotIn" and actual in values:
                return False
            if operator == "Exists" and actual is None:
                return False
            if operator == "DoesNotExist" and actual is not None:
                return False
        return True

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str | None,
        namespace: str | None,
    ) -> dict[str, Any] | None:
        if not name:
            return None
        candidates = objects.get(kind, {})
        direct = candidates.get(name)
        if isinstance(direct, dict):
            if (
                namespace is None
                or direct.get("metadata", {}).get("namespace", "default") == namespace
            ):
                return direct
        for obj in candidates.values():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("name") != name:
                continue
            if (
                namespace is not None
                and metadata.get("namespace", "default") != namespace
            ):
                continue
            return obj
        return None

    def _policy_selects_pod(self, policy: dict[str, Any], pod: dict[str, Any]) -> bool:
        pod_namespace = pod.get("metadata", {}).get("namespace", "default")
        if policy.get("metadata", {}).get("namespace", "default") != pod_namespace:
            return False
        pod_labels = pod.get("metadata", {}).get("labels", {}) or {}
        selector = policy.get("spec", {}).get("podSelector", {})
        return self._match_selector(selector, pod_labels)

    def _policy_is_egress_isolating(self, policy: dict[str, Any]) -> bool:
        spec = policy.get("spec", {})
        policy_types = [str(item) for item in spec.get("policyTypes", []) or []]
        return "Egress" in policy_types or "egress" in spec

    def _selected_egress_policies(
        self, pod: dict[str, Any], objects: dict[str, Any]
    ) -> list[dict[str, Any]]:
        return [
            policy
            for policy in objects.get("networkpolicy", {}).values()
            if isinstance(policy, dict)
            and self._policy_selects_pod(policy, pod)
            and self._policy_is_egress_isolating(policy)
        ]

    def _extract_target(self, message: str, pod_namespace: str) -> TargetInfo | None:
        patterns = (
            r"(?:failed to connect to|because dependency)\s+(?P<target>[a-z0-9.-]+(?::\d+)?)",
            r"dial tcp\s+(?P<target>[a-z0-9.-]+:\d+)",
            r"upstream\s+(?P<target>[a-z0-9.-]+(?::\d+)?)",
        )
        target = None
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                target = match.group("target")
                break
        if target is None:
            svc_match = re.search(
                r"([a-z0-9-]+(?:\.[a-z0-9-]+){0,3}\.svc(?:\.cluster\.local)?(?::\d+)?)",
                message,
            )
            if svc_match:
                target = svc_match.group(1)
        if target is None:
            return None
        match = self.TARGET_RE.fullmatch(target.strip())
        if not match:
            return None

        host = match.group("host").lower()
        port = match.group("port")
        service_name = None
        service_namespace = pod_namespace
        if ".svc" in host:
            parts = host.split(".")
            service_name = parts[0]
            if len(parts) > 1 and parts[1] != "svc":
                service_namespace = parts[1]
        elif "." not in host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            service_name = host
        return {
            "raw": target,
            "host": host,
            "port": int(port) if port else None,
            "service_name": service_name,
            "service_namespace": service_namespace,
        }

    def _service_ready_endpoints(
        self,
        objects: dict[str, Any],
        service_name: str | None,
        service_namespace: str | None,
    ) -> tuple[bool, list[str]]:
        if not service_name:
            return False, []

        ips: list[str] = []
        endpoints = self._find_named_object(
            objects, "endpoints", service_name, service_namespace
        )
        if endpoints:
            for subset in endpoints.get("subsets", []) or []:
                for address in subset.get("addresses", []) or []:
                    ip = address.get("ip")
                    if ip:
                        ips.append(str(ip))

        for slice_obj in objects.get("endpointslice", {}).values():
            if not isinstance(slice_obj, dict):
                continue
            metadata = slice_obj.get("metadata", {})
            if metadata.get("namespace", "default") != service_namespace:
                continue
            labels = metadata.get("labels", {})
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            for endpoint in slice_obj.get("endpoints", []) or []:
                if endpoint.get("conditions", {}).get("ready") is not True:
                    continue
                for address in endpoint.get("addresses", []) or []:
                    ips.append(str(address))

        return bool(ips), ips

    def _namespace_matches(
        self,
        objects: dict[str, Any],
        namespace_selector: dict[str, Any] | None,
        target_namespace: str,
        policy_namespace: str,
    ) -> bool:
        if namespace_selector is None:
            return target_namespace == policy_namespace
        if not namespace_selector:
            return True
        namespace_obj = self._find_named_object(
            objects, "namespace", target_namespace, None
        )
        if not namespace_obj:
            return False
        labels = namespace_obj.get("metadata", {}).get("labels", {}) or {}
        return self._match_selector(namespace_selector, labels)

    def _ip_allowed_by_block(self, ip_value: str, block: dict[str, Any]) -> bool:
        cidr = block.get("cidr")
        if not cidr:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_value)
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        if ip_obj not in network:
            return False
        for except_cidr in block.get("except", []) or []:
            try:
                if ip_obj in ipaddress.ip_network(except_cidr, strict=False):
                    return False
            except ValueError:
                continue
        return True

    def _ports_allow_target(
        self, ports: list[dict[str, Any]] | None, target_port: int | None
    ) -> bool:
        if not ports:
            return True
        if target_port is None:
            return False
        for port_entry in ports:
            port = port_entry.get("port")
            if isinstance(port, int) and port == target_port:
                return True
            if isinstance(port, str):
                try:
                    if int(port) == target_port:
                        return True
                except ValueError:
                    continue
        return False

    def _peer_allows_target(
        self,
        peer: dict[str, Any],
        target: TargetInfo,
        objects: dict[str, Any],
        policy_namespace: str,
    ) -> bool:
        if not peer:
            return True

        service_name = target.get("service_name")
        service_namespace = target.get("service_namespace")
        service_obj = self._find_named_object(
            objects, "service", service_name, service_namespace
        )
        service_selector = (
            service_obj.get("spec", {}).get("selector", {}) if service_obj else {}
        )

        ip_block = peer.get("ipBlock")
        if isinstance(ip_block, dict):
            candidate_ips = []
            host = target.get("host")
            if isinstance(host, str):
                try:
                    ipaddress.ip_address(host)
                    candidate_ips.append(host)
                except ValueError:
                    pass
            if service_obj:
                cluster_ip = service_obj.get("spec", {}).get("clusterIP")
                if cluster_ip and cluster_ip != "None":
                    candidate_ips.append(str(cluster_ip))
            _ready, endpoint_ips = self._service_ready_endpoints(
                objects, service_name, service_namespace
            )
            candidate_ips.extend(endpoint_ips)
            return any(
                self._ip_allowed_by_block(ip_value, ip_block)
                for ip_value in candidate_ips
            )

        if service_name is None:
            return False
        if not isinstance(service_namespace, str):
            return False

        namespace_selector = peer.get("namespaceSelector")
        pod_selector = peer.get("podSelector")
        if namespace_selector is not None and not self._namespace_matches(
            objects, namespace_selector, service_namespace, policy_namespace
        ):
            return False
        if pod_selector is not None:
            if not service_selector or not self._match_selector(
                pod_selector, service_selector
            ):
                return False
        if namespace_selector is None and pod_selector is None:
            return False
        if namespace_selector is None and service_namespace != policy_namespace:
            return False
        return True

    def _target_allowed_by_policy_union(
        self,
        target: TargetInfo,
        policies: list[dict[str, Any]],
        objects: dict[str, Any],
    ) -> bool:
        for policy in policies:
            policy_namespace = policy.get("metadata", {}).get("namespace", "default")
            for rule in policy.get("spec", {}).get("egress", []) or []:
                if not self._ports_allow_target(rule.get("ports"), target.get("port")):
                    continue
                peers = rule.get("to")
                if not peers:
                    return True
                if any(
                    self._peer_allows_target(peer, target, objects, policy_namespace)
                    for peer in peers
                    if isinstance(peer, dict)
                ):
                    return True
        return False

    def _is_dependency_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        pod_namespace: str,
        assume_single_container: bool,
    ) -> TargetInfo | None:
        if not self._container_event_match(
            event, container_name, assume_single_container=assume_single_container
        ):
            return None
        message = self._event_message(event)
        if "probe" in message:
            return None
        if any(marker in message for marker in self.DNS_FAILURE_MARKERS):
            return None
        if not any(marker in message for marker in self.CONNECTIVITY_FAILURE_MARKERS):
            return None
        return self._extract_target(message, pod_namespace)

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
        target: TargetInfo,
        assume_single_container: bool,
    ) -> str | None:
        if self._event_component(event) not in {"", "kubelet"}:
            return None
        if self._event_reason(event) not in {"unhealthy", "failed"}:
            return None
        if not self._container_event_match(
            event, container_name, assume_single_container=assume_single_container
        ):
            return None

        message = self._event_message(event)
        probe_kind = self._probe_kind_from_message(message)
        if probe_kind is None or "fail" not in message:
            return None
        tokens = {target.get("raw"), target.get("host"), target.get("service_name")}
        if any(token and token in message for token in tokens):
            return probe_kind
        if any(marker in message for marker in self.PROBE_COUPLING_MARKERS):
            return probe_kind
        return None

    def _status_for_container(
        self, pod: dict[str, Any], container_name: str
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
    ) -> CandidateInfo | None:
        objects = context.get("objects", {})
        egress_policies = self._selected_egress_policies(pod, objects)
        if not egress_policies:
            return None

        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        pod_namespace = pod.get("metadata", {}).get("namespace", "default")
        container_names = self._candidate_container_names(pod)
        assume_single_container = len(container_names) == 1
        best: CandidateInfo | None = None

        for container_name in container_names:
            status = self._status_for_container(pod, container_name)
            ready = bool(status.get("ready", False))
            restart_count = int(status.get("restartCount", 0) or 0)
            state = status.get("state", {}) or {}
            state_name = (
                "waiting"
                if "waiting" in state
                else "terminated" if "terminated" in state else "running"
            )

            sequences: list[SequenceInfo] = []
            for dep_event in ordered:
                dep_start = self._event_start(dep_event)
                dep_end = self._event_end(dep_event) or dep_start
                if dep_start is None or dep_end is None:
                    continue

                target = self._is_dependency_event(
                    dep_event,
                    container_name=container_name,
                    pod_namespace=pod_namespace,
                    assume_single_container=assume_single_container,
                )
                if target is None:
                    continue
                if self._target_allowed_by_policy_union(
                    target, egress_policies, objects
                ):
                    continue

                service_ready, _ips = self._service_ready_endpoints(
                    objects, target.get("service_name"), target.get("service_namespace")
                )
                if target.get("service_name") and not service_ready:
                    continue

                for probe_event in ordered:
                    probe_start = self._event_start(probe_event)
                    if probe_start is None or probe_start < dep_start:
                        continue
                    if probe_start - dep_end > self.MAX_DEP_TO_PROBE:
                        break
                    probe_kind = self._is_probe_failure_event(
                        probe_event,
                        container_name=container_name,
                        target=target,
                        assume_single_container=assume_single_container,
                    )
                    if probe_kind is None:
                        continue
                    sequences.append(
                        {
                            "dependency_event": dep_event,
                            "probe_event": probe_event,
                            "probe_kind": probe_kind,
                            "strength": min(
                                self._occurrences(dep_event),
                                self._occurrences(probe_event),
                            ),
                            "target": target,
                            "service_ready": service_ready,
                        }
                    )
                    break

            if not sequences:
                continue
            total_strength = sum(seq["strength"] for seq in sequences)
            if (
                len(sequences) < self.MIN_SEQUENCE_OCCURRENCES
                and total_strength < self.MIN_SEQUENCE_OCCURRENCES
            ):
                continue

            dominant: SequenceInfo = max(
                sequences,
                key=lambda seq: (
                    1 if seq["service_ready"] else 0,
                    seq["strength"],
                    self._occurrences(seq["probe_event"]),
                ),
            )
            if dominant["probe_kind"] == "readiness" and ready and total_strength < 3:
                continue

            candidate: CandidateInfo = {
                "container_name": container_name,
                "probe_kind": dominant["probe_kind"],
                "ready": ready,
                "restart_count": restart_count,
                "state_name": state_name,
                "sequence_count": len(sequences),
                "total_strength": total_strength,
                "target": dominant["target"],
                "service_ready": dominant["service_ready"],
                "policy_names": sorted(
                    {
                        str(policy.get("metadata", {}).get("name", "<unknown>"))
                        for policy in egress_policies
                    }
                ),
                "dependency_message": str(
                    dominant["dependency_event"].get("message", "")
                ),
                "probe_message": str(dominant["probe_event"].get("message", "")),
            }
            if best is None or (
                (1 if candidate["service_ready"] else 0),
                candidate["total_strength"],
                candidate["sequence_count"],
            ) > (
                (1 if best["service_ready"] else 0),
                best["total_strength"],
                best["sequence_count"],
            ):
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
            raise ValueError(
                "NetworkPolicyThenProbeFailure requires a Timeline context"
            )
        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "NetworkPolicyThenProbeFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        probe_kind = candidate["probe_kind"]
        target = candidate["target"]
        target_display = target.get("raw") or target.get("host") or "dependency"
        policy_names = candidate["policy_names"]
        primary_policy = policy_names[0] if policy_names else "<unknown>"
        service_name = target.get("service_name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="EGRESS_POLICY_SELECTS_POD",
                    message="An egress-isolating NetworkPolicy selects this pod, so outbound traffic is limited to explicitly allowed destinations",
                    role="policy_context",
                ),
                Cause(
                    code="REQUIRED_DEPENDENCY_NOT_ALLOWED_BY_POLICY",
                    message=f"Effective NetworkPolicy egress rules do not allow required traffic to '{target_display}'",
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="HEALTH_CHECK_DEPENDS_ON_BLOCKED_UPSTREAM",
                    message=f"The {probe_kind} health check depends on upstream dependency reachability, so policy-blocked egress propagates into probe failure",
                    role="configuration_context",
                ),
                Cause(
                    code="PROBE_FAILURE_FOLLOWS_POLICY_BLOCK",
                    message=f"{probe_kind.capitalize()} probe failures begin only after dependency connectivity failures appear on the same container",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"NetworkPolicy selection for this pod includes egress isolation via {', '.join(policy_names)}",
            f"Timeline shows dependency connectivity failures before {probe_kind} probe failures for container '{container_name}'",
            f"Observed {candidate['total_strength']} effective policy-backed dependency -> probe failure occurrence(s) within the recent incident window",
            f"Container '{container_name}' is currently ready={candidate['ready']}, restartCount={candidate['restart_count']}, state={candidate['state_name']}",
        ]
        if candidate["service_ready"] and service_name:
            evidence.append(
                f"Dependency service '{service_name}' still has ready endpoints, which points to pod egress isolation rather than a backend outage"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                f"{probe_kind.capitalize()} probe failures are downstream of policy-blocked dependency traffic"
            ],
            f"networkpolicy:{primary_policy}": [
                "This policy selects the pod for egress isolation and does not effectively allow the required dependency traffic"
            ],
            f"container:{container_name}": [
                candidate["dependency_message"],
                candidate["probe_message"],
            ],
        }
        if candidate["service_ready"] and service_name:
            object_evidence[f"service:{service_name}"] = [
                "The backing Service still has ready endpoints during the probe failure sequence"
            ]

        return {
            "root_cause": "A NetworkPolicy blocks required dependency egress, and probe failures follow because the health check depends on that blocked upstream",
            "confidence": 0.96 if candidate["service_ready"] else 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The pod is selected by a deny-all or overly narrow egress NetworkPolicy that does not allow required dependency traffic",
                f"The {probe_kind} endpoint is coupled to dependency reachability instead of local container health",
                "Backend services are healthy, but only this pod cannot reach them because policy enforcement isolates its outbound traffic",
            ],
            "suggested_checks": [
                f"kubectl describe networkpolicy {primary_policy}",
                f"kubectl describe pod {pod_name}",
                "Review the effective union of egress rules for this pod and verify the dependency destination and port are explicitly allowed",
                "Exec into a debug pod with the same labels or policy selection and test connectivity to the dependency target",
            ],
        }
