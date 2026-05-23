from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CoreDNSUnavailableRule(FailureRule):
    """
    Detects workload DNS failures whose root cause is degraded CoreDNS.

    Real-world interpretation:
    - a workload is reporting DNS lookup timeouts, SERVFAILs, or resolver errors
    - the kube-dns/CoreDNS serving layer is degraded at the same time
    - CoreDNS has no ready endpoints, no available replicas, unhealthy pods, or
      recent kube-system events showing CoreDNS probe/backoff failures

    This rule intentionally does not fire for a DNS symptom alone; in that case
    DNSResolutionFailure remains the fallback.
    """

    name = "CoreDNSUnavailable"
    category = "Networking"
    severity = "High"
    priority = 70
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "deployment",
            "service",
            "endpoints",
            "endpointslice",
        ],
    }

    blocks = [
        "DNSResolutionFailure",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
    ]

    WINDOW_MINUTES = 20
    DNS_FAILURE_MARKERS = (
        "dns lookup failed",
        "dns resolution",
        "dns",
        "cannot resolve",
        "could not resolve",
        "failed to resolve",
        "lookup ",
        "no such host",
        "server misbehaving",
        "temporary failure in name resolution",
        "name or service not known",
        "servfail",
    )
    DNS_TRANSPORT_MARKERS = (
        "read udp",
        "read tcp",
        "i/o timeout",
        "connection refused",
    )
    NON_DNS_EXCLUSIONS = (
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "x509:",
        "certificate",
    )
    COREDNS_IDENTIFIERS = (
        "coredns",
        "kube-dns",
        "k8s-app=kube-dns",
        "k8s-app: kube-dns",
    )
    COREDNS_FAILURE_REASONS = {
        "backoff",
        "unhealthy",
        "failed",
        "failedscheduling",
        "failedmount",
        "killing",
    }
    COREDNS_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "crashloopbackoff",
        "back-off restarting failed container",
        'no endpoints available for service "kube-dns"',
        "no endpoints available for service kube-dns",
        "endpoints not found",
        "connection refused",
        "plugin/errors",
        "panic",
        "loop detected",
    )
    RECOVERY_REASONS = {
        "Started",
        "Pulled",
        "Created",
        "Ready",
    }
    LOOKUP_TARGET_RE = re.compile(
        r"lookup\s+([a-z0-9.-]+)",
        re.IGNORECASE,
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
        indexed = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _targets_current_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind", "") or "").lower()
        if kind and kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _is_workload_dns_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False
        message = self._message(event).lower()
        if any(marker in message for marker in self.NON_DNS_EXCLUSIONS):
            return False
        if any(marker in message for marker in self.DNS_FAILURE_MARKERS):
            return True
        return ":53" in message and any(
            marker in message for marker in self.DNS_TRANSPORT_MARKERS
        )

    def _lookup_target(self, message: str) -> str | None:
        matches = self.LOOKUP_TARGET_RE.findall(message)
        for candidate in reversed(matches):
            lowered = candidate.lower().strip(".")
            if lowered not in {"failed", "dns"}:
                return lowered
        return None

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{key}={value}".lower() for key, value in labels.items())

    def _is_coredns_object(self, obj: dict[str, Any]) -> bool:
        namespace = self._object_namespace(obj)
        if namespace != "kube-system":
            return False

        text = " ".join(
            value.lower()
            for value in (
                self._object_name(obj),
                self._labels_text(obj),
                str(obj.get("metadata", {}).get("generateName") or ""),
            )
            if value
        )
        return any(identifier in text for identifier in self.COREDNS_IDENTIFIERS)

    def _ready_coredns_pods(self, objects: dict[str, Any]) -> list[dict[str, Any]]:
        ready: list[dict[str, Any]] = []
        for pod in objects.get("pod", {}).values():
            if not isinstance(pod, dict) or not self._is_coredns_object(pod):
                continue
            if pod.get("status", {}).get("phase") != "Running":
                continue
            conditions = pod.get("status", {}).get("conditions", []) or []
            if any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in conditions
            ):
                ready.append(pod)
        return ready

    def _degraded_coredns_pods(self, objects: dict[str, Any]) -> list[dict[str, Any]]:
        degraded: list[dict[str, Any]] = []
        for pod in objects.get("pod", {}).values():
            if not isinstance(pod, dict) or not self._is_coredns_object(pod):
                continue
            status = pod.get("status", {})
            phase = status.get("phase")
            if phase not in {"Running", "Succeeded"}:
                degraded.append(pod)
                continue

            conditions = status.get("conditions", []) or []
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in conditions
            )
            if not ready:
                degraded.append(pod)
                continue

            for container in status.get("containerStatuses", []) or []:
                state = container.get("state", {}) or {}
                waiting = state.get("waiting", {}) or {}
                if waiting.get("reason") in {
                    "CrashLoopBackOff",
                    "CreateContainerConfigError",
                    "ImagePullBackOff",
                    "ErrImagePull",
                }:
                    degraded.append(pod)
                    break
        return degraded

    def _deployment_unavailable(
        self,
        objects: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        for deployment in objects.get("deployment", {}).values():
            if not isinstance(deployment, dict) or not self._is_coredns_object(
                deployment
            ):
                continue
            spec = deployment.get("spec", {})
            status = deployment.get("status", {})
            desired = int(spec.get("replicas", status.get("replicas", 0)) or 0)
            available = int(status.get("availableReplicas", 0) or 0)
            unavailable = int(status.get("unavailableReplicas", 0) or 0)

            available_condition_false = any(
                condition.get("type") == "Available"
                and condition.get("status") == "False"
                for condition in status.get("conditions", []) or []
            )
            if desired > 0 and (available == 0 or unavailable >= desired):
                reason = (
                    f"CoreDNS Deployment has desired={desired}, "
                    f"available={available}, unavailable={unavailable}"
                )
                return deployment, reason
            if available_condition_false:
                return deployment, "CoreDNS Deployment condition Available=False"
        return None, None

    def _service_is_kube_dns(self, service: dict[str, Any]) -> bool:
        metadata = service.get("metadata", {})
        return (
            metadata.get("name") == "kube-dns"
            and metadata.get("namespace", "kube-system") == "kube-system"
        )

    def _ready_addresses_for_endpoints(self, endpoints: dict[str, Any]) -> list[str]:
        addresses: list[str] = []
        for subset in endpoints.get("subsets", []) or []:
            for address in subset.get("addresses", []) or []:
                ip = address.get("ip")
                if isinstance(ip, str) and ip:
                    addresses.append(ip)
        return addresses

    def _ready_addresses_for_slices(
        self,
        slices: dict[str, Any],
    ) -> list[str]:
        addresses: list[str] = []
        for slice_obj in slices.values():
            if not isinstance(slice_obj, dict):
                continue
            labels = slice_obj.get("metadata", {}).get("labels", {}) or {}
            namespace = slice_obj.get("metadata", {}).get("namespace", "kube-system")
            if namespace != "kube-system":
                continue
            if labels.get("kubernetes.io/service-name") != "kube-dns":
                continue
            for endpoint in slice_obj.get("endpoints", []) or []:
                conditions = endpoint.get("conditions", {}) or {}
                if conditions.get("ready") is not True:
                    continue
                for address in endpoint.get("addresses", []) or []:
                    if isinstance(address, str) and address:
                        addresses.append(address)
        return addresses

    def _kube_dns_endpoints_unavailable(
        self,
        objects: dict[str, Any],
    ) -> tuple[bool, str | None]:
        kube_dns_service_seen = any(
            isinstance(service, dict) and self._service_is_kube_dns(service)
            for service in objects.get("service", {}).values()
        )

        endpoints_obj = next(
            (
                endpoint
                for endpoint in objects.get("endpoints", {}).values()
                if isinstance(endpoint, dict)
                and endpoint.get("metadata", {}).get("name") == "kube-dns"
                and endpoint.get("metadata", {}).get("namespace", "kube-system")
                == "kube-system"
            ),
            None,
        )
        ready_endpoints = (
            self._ready_addresses_for_endpoints(endpoints_obj) if endpoints_obj else []
        )
        ready_slices = self._ready_addresses_for_slices(
            objects.get("endpointslice", {})
        )

        if endpoints_obj is not None and not ready_endpoints:
            return True, "kube-dns Endpoints object has no ready addresses"
        if objects.get("endpointslice") and not ready_slices and kube_dns_service_seen:
            return True, "kube-dns EndpointSlices have no ready endpoints"
        return False, None

    def _event_involves_coredns(self, event: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        involved_text = ""
        if isinstance(involved, dict):
            involved_text = " ".join(
                str(value).lower()
                for value in (
                    involved.get("namespace"),
                    involved.get("name"),
                    involved.get("kind"),
                    involved.get("fieldPath"),
                )
                if value
            )
        text = f"{involved_text} {self._message(event).lower()}"
        return any(identifier in text for identifier in self.COREDNS_IDENTIFIERS)

    def _is_coredns_failure_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_coredns(event):
            return False
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        return reason in self.COREDNS_FAILURE_REASONS or any(
            marker in message for marker in self.COREDNS_FAILURE_MARKERS
        )

    def _coredns_recovered_after(
        self,
        timeline: Timeline,
        failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if self._reason(event) not in self.RECOVERY_REASONS:
                continue
            if not self._event_involves_coredns(event):
                continue
            event_at = self._event_time(event)
            if failure_at is None or event_at is None or event_at >= failure_at:
                return True
        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        recent_events = self._ordered_recent_events(timeline)
        dns_events = [
            event
            for event in recent_events
            if self._is_workload_dns_failure(event, pod)
        ]
        if not dns_events:
            return None

        objects = context.get("objects", {})
        degraded_signals: list[str] = []
        object_evidence: dict[str, list[str]] = {}

        endpoints_unavailable, endpoint_reason = self._kube_dns_endpoints_unavailable(
            objects
        )
        if endpoints_unavailable and endpoint_reason:
            degraded_signals.append(endpoint_reason)
            object_evidence["service:kube-dns"] = [endpoint_reason]

        deployment, deployment_reason = self._deployment_unavailable(objects)
        if deployment and deployment_reason:
            degraded_signals.append(deployment_reason)
            object_evidence["deployment:coredns"] = [deployment_reason]

        degraded_pods = self._degraded_coredns_pods(objects)
        ready_pods = self._ready_coredns_pods(objects)
        if degraded_pods and not ready_pods:
            pod_names = ", ".join(
                self._object_name(pod_obj) for pod_obj in degraded_pods[:3]
            )
            degraded_signals.append(
                f"No ready CoreDNS pods; degraded pod(s): {pod_names}"
            )
            for pod_obj in degraded_pods[:3]:
                object_evidence[f"pod:{self._object_name(pod_obj)}"] = [
                    "CoreDNS pod is not Ready during workload DNS failures"
                ]

        coredns_events = [
            event for event in recent_events if self._is_coredns_failure_event(event)
        ]
        if coredns_events:
            representative_coredns = coredns_events[-1]
            degraded_signals.append(
                f"Recent CoreDNS event: {self._message(representative_coredns)}"
            )
            object_evidence.setdefault("timeline:coredns", []).append(
                self._message(representative_coredns)
            )

        if not degraded_signals:
            return None

        latest_core_failure_at = (
            self._event_time(coredns_events[-1]) if coredns_events else None
        )
        if coredns_events and self._coredns_recovered_after(
            timeline,
            latest_core_failure_at,
        ):
            return None

        representative_dns = dns_events[-1]
        dns_occurrences = sum(self._occurrences(event) for event in dns_events)
        coredns_occurrences = sum(self._occurrences(event) for event in coredns_events)
        duration_seconds = timeline.duration_between(
            lambda event: self._is_workload_dns_failure(event, pod)
            or self._is_coredns_failure_event(event)
        )

        return {
            "dns_events": dns_events,
            "dns_occurrences": dns_occurrences,
            "representative_dns_message": self._message(representative_dns),
            "lookup_target": self._lookup_target(self._message(representative_dns)),
            "degraded_signals": list(dict.fromkeys(degraded_signals)),
            "object_evidence": object_evidence,
            "coredns_occurrences": coredns_occurrences,
            "duration_seconds": duration_seconds,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CoreDNSUnavailable requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("CoreDNSUnavailable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        lookup_target = candidate["lookup_target"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_REQUIRES_CLUSTER_DNS",
                    message="Workload depends on cluster DNS resolution for service discovery or startup dependencies",
                    role="runtime_context",
                ),
                Cause(
                    code="COREDNS_UNAVAILABLE",
                    message="CoreDNS/kube-dns is degraded and cannot reliably answer DNS queries",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_DNS_RESOLUTION_BLOCKED",
                    message="Pod DNS lookups fail because the cluster DNS backend is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} has DNS resolution failures in the recent incident window",
            f"Representative workload DNS failure: {candidate['representative_dns_message']}",
            f"Observed {candidate['dns_occurrences']} workload DNS failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            "CoreDNS degradation is evidenced separately from the workload DNS symptom",
        ]
        if lookup_target:
            evidence.append(f"DNS failures target hostname '{lookup_target}'")
        evidence.extend(candidate["degraded_signals"])
        if candidate["coredns_occurrences"]:
            evidence.append(
                f"Observed {candidate['coredns_occurrences']} CoreDNS failure event occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )
        if candidate["duration_seconds"]:
            evidence.append(
                f"DNS/CoreDNS failure signals persisted for {candidate['duration_seconds']/60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                candidate["representative_dns_message"],
            ],
            **candidate["object_evidence"],
        }

        return {
            "root_cause": "CoreDNS is unavailable or has no ready endpoints",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "CoreDNS pods are crashlooping, failing probes, or unavailable",
                "The kube-dns Service has no ready CoreDNS endpoints",
                "The CoreDNS Deployment cannot maintain available replicas",
                "CoreDNS configuration, upstream DNS forwarding, or node pressure is causing the DNS backend to fail",
            ],
            "suggested_checks": [
                "kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide",
                "kubectl describe deployment coredns -n kube-system",
                "kubectl get endpoints kube-dns -n kube-system",
                "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=100",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
