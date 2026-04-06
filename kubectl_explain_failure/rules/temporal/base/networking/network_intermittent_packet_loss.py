from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class RecoveryEpisode(TypedDict):
    failure_event: dict[str, Any]
    success_event: dict[str, Any]
    target: str
    service_name: str | None
    service_namespace: str | None
    service_ready: bool


class Candidate(TypedDict):
    container_name: str
    target: str
    service_name: str | None
    service_ready: bool
    episode_count: int
    failure_count: int
    success_count: int
    pod_ready: bool
    representative_failure: str
    representative_success: str


class NetworkIntermittentPacketLossRule(FailureRule):
    """
    Detects transient packet-loss-like networking where DNS lookups time out,
    recover, and then fail again.
    """

    name = "NetworkIntermittentPacketLoss"
    category = "Temporal"
    priority = 67
    deterministic = False
    phases = ["Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["service", "endpoints", "endpointslice"],
    }
    blocks = [
        "DNSResolutionFailure",
        "IntermittentNetworkFlapping",
        "ReadinessProbeFailure",
    ]

    WINDOW_MINUTES = 20
    MAX_RECOVERY_GAP = timedelta(minutes=4)

    LOSS_MARKERS = (
        "i/o timeout",
        "read udp",
        "context deadline exceeded",
        "connection reset by peer",
        "server misbehaving",
        "timeout",
    )
    DNS_MARKERS = ("dns", "lookup ")
    MISCONFIG_MARKERS = ("no such host", "nxdomain", "cannot resolve")
    SUCCESS_REASONS = {"ready"}
    SUCCESS_MARKERS = ("probe succeeded", "became ready", "container became ready")
    LOOKUP_ON_RE = re.compile(r"lookup\s+([a-z0-9.-]+)\s+on\s+", re.IGNORECASE)
    LOOKUP_FOR_RE = re.compile(r"failed\s+for\s+([a-z0-9.-]+):", re.IGNORECASE)

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

    def _component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _container_names(self, pod: dict[str, Any]) -> list[str]:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        names = [
            str(status.get("name", "")) for status in statuses if status.get("name")
        ]
        if names:
            return names
        containers = pod.get("spec", {}).get("containers", []) or []
        return [
            str(container.get("name", ""))
            for container in containers
            if container.get("name")
        ]

    def _container_match(
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
        message = self._message(event)
        return (
            f'container "{container_name.lower()}"' in message
            or f"containers{{{container_name.lower()}}}" in message
            or (assume_single_container and "container " not in message)
        )

    def _find_named_object(
        self, objects: dict[str, Any], kind: str, name: str, namespace: str | None
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict):
            if (
                namespace is None
                or direct.get("metadata", {}).get("namespace", "default") == namespace
            ):
                return direct
        for obj in objects.get(kind, {}).values():
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

    def _service_ready(
        self, objects: dict[str, Any], service_name: str, namespace: str
    ) -> bool:
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
        return False

    def _dns_failure_target(self, message: str) -> str | None:
        if not any(marker in message for marker in self.DNS_MARKERS):
            return None
        if any(marker in message for marker in self.MISCONFIG_MARKERS):
            return None
        if not any(marker in message for marker in self.LOSS_MARKERS):
            return None
        match = self.LOOKUP_ON_RE.search(message) or self.LOOKUP_FOR_RE.search(message)
        return match.group(1).lower() if match else None

    def _failure_event(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> tuple[str, str | None, str | None] | None:
        if not self._container_match(
            event, container_name, assume_single_container=assume_single_container
        ):
            return None
        target = self._dns_failure_target(self._message(event))
        if target is None:
            return None
        service_name = None
        service_namespace = None
        if ".svc" in target:
            parts = target.split(".")
            service_name = parts[0]
            service_namespace = (
                parts[1] if len(parts) > 1 and parts[1] != "svc" else "default"
            )
        return target, service_name, service_namespace

    def _success_event(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not self._container_match(
            event, container_name, assume_single_container=assume_single_container
        ):
            return False
        if self._component(event) not in {"", "kubelet"}:
            return False
        reason = self._reason(event)
        message = self._message(event)
        return reason in self.SUCCESS_REASONS or any(
            marker in message for marker in self.SUCCESS_MARKERS
        )

    def _best_candidate(
        self, pod: dict[str, Any], timeline: Timeline, context: dict[str, Any]
    ) -> Candidate | None:
        objects = context.get("objects", {})
        ordered = self._ordered_recent(timeline)
        if not ordered:
            return None

        assume_single_container = len(self._container_names(pod)) == 1
        best: Candidate | None = None

        for container_name in self._container_names(pod):
            episodes: list[RecoveryEpisode] = []
            failure_count = 0
            last_success_ts: datetime | None = None

            for index, event in enumerate(ordered):
                failure = self._failure_event(
                    event,
                    container_name,
                    assume_single_container=assume_single_container,
                )
                if failure is None:
                    continue

                failure_count += 1
                target, service_name, service_namespace = failure
                if service_name and service_namespace:
                    if (
                        self._find_named_object(
                            objects, "service", service_name, service_namespace
                        )
                        is None
                    ):
                        continue
                    if not self._service_ready(
                        objects, service_name, service_namespace
                    ):
                        continue

                failure_ts = self._event_ts(event)
                if failure_ts is None or (
                    last_success_ts and failure_ts <= last_success_ts
                ):
                    continue

                for success_event in ordered[index + 1 :]:
                    success_ts = self._event_ts(success_event)
                    if success_ts is None or success_ts < failure_ts:
                        continue
                    if success_ts - failure_ts > self.MAX_RECOVERY_GAP:
                        break
                    if not self._success_event(
                        success_event,
                        container_name,
                        assume_single_container=assume_single_container,
                    ):
                        continue
                    episodes.append(
                        {
                            "failure_event": event,
                            "success_event": success_event,
                            "target": target,
                            "service_name": service_name,
                            "service_namespace": service_namespace,
                            "service_ready": bool(service_name and service_namespace),
                        }
                    )
                    last_success_ts = success_ts
                    break

            success_count = len(episodes)
            if len(episodes) < 2 or failure_count < 2 or success_count < 2:
                continue

            status: dict[str, Any] = next(
                (
                    s
                    for s in pod.get("status", {}).get("containerStatuses", []) or []
                    if str(s.get("name", "")) == container_name
                ),
                {},
            )
            representative = episodes[0]
            candidate: Candidate = {
                "container_name": container_name,
                "target": representative["target"],
                "service_name": representative["service_name"],
                "service_ready": representative["service_ready"],
                "episode_count": len(episodes),
                "failure_count": failure_count,
                "success_count": success_count,
                "pod_ready": bool(status.get("ready", False)),
                "representative_failure": str(
                    representative["failure_event"].get("message", "")
                ),
                "representative_success": str(
                    representative["success_event"].get("message", "")
                ),
            }
            if best is None or (
                1 if candidate["service_ready"] else 0,
                candidate["episode_count"],
                candidate["success_count"],
            ) > (
                1 if best["service_ready"] else 0,
                best["episode_count"],
                best["success_count"],
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
                "NetworkIntermittentPacketLoss requires a Timeline context"
            )
        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "NetworkIntermittentPacketLoss explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        target = candidate["target"]
        service_name = candidate["service_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="DNS_REQUIRED_FOR_DEPENDENCY_TRAFFIC",
                    message="The workload depends on repeated DNS lookups to reach a required upstream dependency",
                    role="runtime_context",
                ),
                Cause(
                    code="INTERMITTENT_PACKET_LOSS_INFERRED",
                    message="Timeout-style DNS failures alternate with recovery, which is more consistent with intermittent packet loss or DNS path instability than steady misconfiguration",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="DNS_FAILURES_AND_RECOVERIES_ALTERNATE",
                    message="The same container repeatedly flips between DNS failure and recovery within a short incident window",
                    role="network_intermediate",
                ),
                Cause(
                    code="WORKLOAD_CONNECTIVITY_UNSTABLE",
                    message="Application connectivity is unstable because dependency name resolution intermittently fails and then recovers",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Timeline shows {candidate['episode_count']} DNS failure -> recovery episode(s) for container '{candidate['container_name']}' within {self.WINDOW_MINUTES} minutes",
            f"DNS failures repeatedly target '{target}' and are followed by recovery signals on the same container",
            f"Container '{candidate['container_name']}' is currently ready={candidate['pod_ready']}, indicating the issue is intermittent rather than constantly failing",
        ]
        if candidate["service_ready"] and service_name:
            evidence.append(
                f"Dependency service '{service_name}' still has ready endpoints during the incident window, which makes steady backend outage less likely"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "The pod alternates between DNS-related connectivity failure and recovery"
            ],
            f"container:{candidate['container_name']}": [
                candidate["representative_failure"],
                candidate["representative_success"],
            ],
        }
        if candidate["service_ready"] and service_name:
            object_evidence[f"service:{service_name}"] = [
                "Service backends remained ready while DNS failures intermittently appeared"
            ]

        return {
            "root_cause": "Intermittent packet loss or DNS path instability is causing alternating DNS failures and recoveries",
            "confidence": 0.86 if candidate["service_ready"] else 0.81,
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The pod-to-DNS network path is intermittently dropping or delaying packets",
                "Overlay or node networking is causing transient DNS timeouts under load",
                "CoreDNS traffic is occasionally timing out even though the dependency service itself remains healthy",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Run repeated DNS lookups from a debug pod on the same node and watch for timeout spikes",
                "Inspect CoreDNS latency, timeout, and SERVFAIL metrics during the incident window",
                "Check node and CNI telemetry for packet drops, retransmits, or overlay-network instability",
            ],
        }
