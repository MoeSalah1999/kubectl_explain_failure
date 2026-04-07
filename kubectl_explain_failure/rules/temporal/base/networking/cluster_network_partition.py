from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class PartitionEpisode(TypedDict):
    dns_event: dict[str, Any]
    api_event: dict[str, Any]
    recovery_event: dict[str, Any]
    dns_target: str
    api_target: str


class Candidate(TypedDict):
    container_name: str
    episode_count: int
    total_strength: int
    dns_target: str
    api_target: str
    pod_ready: bool
    representative_dns: str
    representative_api: str
    representative_recovery: str
    kube_dns_ready: bool | None
    kubernetes_service_ready: bool | None


class ClusterNetworkPartitionRule(FailureRule):
    """
    Detects a recovered cluster-network outage episode where multiple internal
    control-plane paths fail together and later recover.
    """

    name = "ClusterNetworkPartition"
    category = "Temporal"
    priority = 69
    deterministic = False
    phases = ["Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["service", "endpoints", "endpointslice"],
    }
    blocks = [
        "DNSResolutionFailure",
        "NetworkIntermittentPacketLoss",
        "IntermittentNetworkFlapping",
    ]

    WINDOW_MINUTES = 20
    MAX_DNS_TO_API_GAP = timedelta(minutes=3)
    MAX_API_TO_RECOVERY_GAP = timedelta(minutes=5)

    DNS_TIMEOUT_MARKERS = (
        "i/o timeout",
        "read udp",
        "context deadline exceeded",
        "network is unreachable",
        "no route to host",
        "timeout",
    )
    DNS_EXCLUSION_MARKERS = (
        "no such host",
        "nxdomain",
        "cannot resolve",
        "server misbehaving",
    )
    API_FAILURE_MARKERS = (
        "i/o timeout",
        "context deadline exceeded",
        "network is unreachable",
        "no route to host",
        "tls handshake timeout",
        "connection timed out",
        "timeout",
    )
    API_EXCLUSION_MARKERS = (
        "forbidden",
        "unauthorized",
        "x509",
        "certificate",
        "bad certificate",
        "connection refused",
    )
    RECOVERY_REASONS = {"ready"}
    RECOVERY_MARKERS = (
        "probe succeeded",
        "became ready",
        "reconnected",
        "connectivity restored",
        "network restored",
        "api server reachable again",
    )
    LOOKUP_FAILED_FOR_RE = re.compile(
        r"dns\s+lookup\s+failed\s+for\s+([a-z0-9.-]+):",
        re.IGNORECASE,
    )
    LOOKUP_TARGET_RE = re.compile(r"lookup\s+([a-z0-9.-]+)", re.IGNORECASE)
    URL_TARGET_RE = re.compile(r"https?://([^/\"\s]+)", re.IGNORECASE)

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

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _container_names(self, pod: dict[str, Any]) -> list[str]:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        names = [
            str(status.get("name", "")) for status in statuses if status.get("name")
        ]
        if names:
            return names
        return [
            str(container.get("name", ""))
            for container in pod.get("spec", {}).get("containers", []) or []
            if container.get("name")
        ]

    def _container_match(
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
            if field_path:
                return lowered in field_path

        message = self._message(event)
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"containers{{{lowered}}}",
        )
        return any(pattern in message for pattern in patterns) or (
            assume_single_container and "container " not in message
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

    def _dns_failure_target(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> str | None:
        if not self._container_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None
        message = self._message(event)
        if "dns" not in message and "lookup " not in message:
            return None
        if any(marker in message for marker in self.DNS_EXCLUSION_MARKERS):
            return None
        if not any(marker in message for marker in self.DNS_TIMEOUT_MARKERS):
            return None
        match = self.LOOKUP_FAILED_FOR_RE.search(
            message
        ) or self.LOOKUP_TARGET_RE.search(message)
        return match.group(1).lower() if match else None

    def _api_target_markers(self, objects: dict[str, Any]) -> set[str]:
        markers = {
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
        }
        kubernetes_service = self._find_named_object(
            objects,
            "service",
            "kubernetes",
            "default",
        )
        if kubernetes_service:
            cluster_ip = kubernetes_service.get("spec", {}).get("clusterIP")
            if cluster_ip and cluster_ip != "None":
                markers.add(str(cluster_ip).lower())
                markers.add(f"{str(cluster_ip).lower()}:443")
        return markers

    def _api_failure_target(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
        objects: dict[str, Any],
    ) -> str | None:
        if not self._container_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None
        message = self._message(event)
        if any(marker in message for marker in self.API_EXCLUSION_MARKERS):
            return None
        if not any(marker in message for marker in self.API_FAILURE_MARKERS):
            return None

        target_markers = self._api_target_markers(objects)
        url_match = self.URL_TARGET_RE.search(message)
        if url_match:
            target = url_match.group(1).lower()
            if any(marker in target for marker in target_markers):
                return target

        for marker in target_markers:
            if marker in message:
                return marker
        return None

    def _recovery_event(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not self._container_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False
        reason = self._reason(event)
        message = self._message(event)
        return reason in self.RECOVERY_REASONS or any(
            marker in message for marker in self.RECOVERY_MARKERS
        )

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> Candidate | None:
        objects = context.get("objects", {})
        ordered = self._ordered_recent(timeline)
        if not ordered:
            return None

        kube_dns_ready = self._service_ready(objects, "kube-dns", "kube-system")
        kubernetes_service_ready = self._service_ready(objects, "kubernetes", "default")
        if kube_dns_ready is False or kubernetes_service_ready is False:
            return None

        assume_single_container = len(self._container_names(pod)) == 1
        best: Candidate | None = None

        for container_name in self._container_names(pod):
            episodes: list[PartitionEpisode] = []
            total_strength = 0
            last_recovery_ts: datetime | None = None

            for index, event in enumerate(ordered):
                dns_target = self._dns_failure_target(
                    event,
                    container_name,
                    assume_single_container=assume_single_container,
                )
                if dns_target is None:
                    continue

                dns_ts = self._event_ts(event)
                if dns_ts is None:
                    continue
                if last_recovery_ts and dns_ts <= last_recovery_ts:
                    continue

                for api_index in range(index + 1, len(ordered)):
                    api_event = ordered[api_index]
                    api_ts = self._event_ts(api_event)
                    if api_ts is None or api_ts < dns_ts:
                        continue
                    if api_ts - dns_ts > self.MAX_DNS_TO_API_GAP:
                        break

                    api_target = self._api_failure_target(
                        api_event,
                        container_name,
                        assume_single_container=assume_single_container,
                        objects=objects,
                    )
                    if api_target is None:
                        continue

                    for recovery_event in ordered[api_index + 1 :]:
                        recovery_ts = self._event_ts(recovery_event)
                        if recovery_ts is None or recovery_ts < api_ts:
                            continue
                        if recovery_ts - api_ts > self.MAX_API_TO_RECOVERY_GAP:
                            break
                        if not self._recovery_event(
                            recovery_event,
                            container_name,
                            assume_single_container=assume_single_container,
                        ):
                            continue

                        episodes.append(
                            {
                                "dns_event": event,
                                "api_event": api_event,
                                "recovery_event": recovery_event,
                                "dns_target": dns_target,
                                "api_target": api_target,
                            }
                        )
                        total_strength += min(
                            self._occurrences(event),
                            self._occurrences(api_event),
                        )
                        last_recovery_ts = recovery_ts
                        break

                    if last_recovery_ts is not None and last_recovery_ts > api_ts:
                        break

            if not episodes:
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
                "episode_count": len(episodes),
                "total_strength": max(total_strength, len(episodes)),
                "dns_target": representative["dns_target"],
                "api_target": representative["api_target"],
                "pod_ready": bool(status.get("ready", False)),
                "representative_dns": str(
                    representative["dns_event"].get("message", "")
                ).strip(),
                "representative_api": str(
                    representative["api_event"].get("message", "")
                ).strip(),
                "representative_recovery": str(
                    representative["recovery_event"].get("message", "")
                ).strip(),
                "kube_dns_ready": kube_dns_ready,
                "kubernetes_service_ready": kubernetes_service_ready,
            }
            if best is None or (
                int(candidate["kube_dns_ready"] is True)
                + int(candidate["kubernetes_service_ready"] is True),
                candidate["episode_count"],
                candidate["total_strength"],
            ) > (
                int(best["kube_dns_ready"] is True)
                + int(best["kubernetes_service_ready"] is True),
                best["episode_count"],
                best["total_strength"],
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
            raise ValueError("ClusterNetworkPartition requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("ClusterNetworkPartition explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_DNS_AND_API_REQUIRED",
                    message="The workload depends on both cluster DNS and Kubernetes API reachability to function normally",
                    role="runtime_context",
                ),
                Cause(
                    code="MULTI_PATH_CLUSTER_NETWORK_OUTAGE",
                    message="DNS and Kubernetes API traffic failed in the same short outage window, which is more consistent with a transient cluster network partition than a single service-specific outage",
                    role="infrastructure_root",
                    blocking=False,
                ),
                Cause(
                    code="NETWORK_CONNECTIVITY_RECOVERED",
                    message="Connectivity later recovered without a configuration change, indicating the outage was transient",
                    role="temporal_context",
                ),
                Cause(
                    code="WORKLOAD_EXPERIENCED_RECOVERED_PARTITION",
                    message="The workload experienced a temporary cluster-network partition and then recovered",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Timeline shows {candidate['episode_count']} recovered cluster-network outage episode(s) for container '{candidate['container_name']}' within {self.WINDOW_MINUTES} minutes",
            f"DNS failure to '{candidate['dns_target']}' is followed by Kubernetes API reachability failure to '{candidate['api_target']}' before recovery",
            f"Representative recovery signal: {candidate['representative_recovery']}",
            f"Container '{candidate['container_name']}' is currently ready={candidate['pod_ready']}, which is consistent with a recovered partition rather than a steady outage",
        ]
        if (
            candidate["kube_dns_ready"] is True
            and candidate["kubernetes_service_ready"] is True
        ):
            evidence.append(
                "Both kube-dns and kubernetes services still had ready endpoints during the incident window, which makes a single backend outage less likely"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "The pod lost both DNS and Kubernetes API reachability before recovering"
            ],
            f"container:{candidate['container_name']}": [
                candidate["representative_dns"],
                candidate["representative_api"],
                candidate["representative_recovery"],
            ],
        }
        if candidate["kube_dns_ready"] is True:
            object_evidence["service:kube-dns"] = [
                "CoreDNS service still had ready endpoints during the outage episode"
            ]
        if candidate["kubernetes_service_ready"] is True:
            object_evidence["service:kubernetes"] = [
                "Kubernetes API service still had ready endpoints during the outage episode"
            ]

        confidence = 0.91
        if (
            candidate["kube_dns_ready"] is True
            and candidate["kubernetes_service_ready"] is True
        ):
            confidence = 0.94

        return {
            "root_cause": "A transient cluster network partition caused DNS and Kubernetes API reachability to fail before connectivity recovered",
            "confidence": confidence,
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Overlay or CNI networking temporarily partitioned the pod from core cluster services",
                "Node-to-service routing or conntrack state briefly broke reachability to both CoreDNS and the Kubernetes API",
                "A transient control-plane network interruption isolated workloads from internal service VIPs before routes recovered",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect CoreDNS and apiserver connectivity metrics around the outage window",
                "Check node, kube-proxy, and CNI telemetry for packet drops, route reprogramming, or conntrack churn",
                "Compare whether other pods on the same node also lost DNS and Kubernetes API reachability during the same interval",
            ],
        }
