from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DualStackIPFamilyMismatchRule(FailureRule):
    """
    Detects failures caused by IPv4/IPv6 family mismatches between Pods,
    Services, EndpointSlices, and cluster networking configuration.

    Real-world behavior:

    - Service advertises IPv6 endpoints while workload only supports IPv4.
    - EndpointSlice family differs from Service family.
    - Service requires dual-stack but only one family exists.
    - Cluster dual-stack rollout leaves workloads partially migrated.
    - StatefulSet headless service publishes only one address family.
    - CNI allocates only IPv4 while Services require IPv6 reachability.

    Exclusions:

    - DNS failures
    - NetworkPolicy failures
    - NAT failures
    - Generic CNI outages
    - Missing endpoints unrelated to IP family
    """

    name = "DualStackIPFamilyMismatch"
    category = "Networking"
    severity = "High"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "service",
            "endpointslice",
            "pod",
            "node",
        ],
    }

    blocks = [
        "ServiceConnectivityFailure",
    ]

    WINDOW_MINUTES = 20

    IPV4_MARKERS = (
        "ipv4",
        "4",
    )

    IPV6_MARKERS = (
        "ipv6",
        "6",
    )

    MISMATCH_MARKERS = (
        "address family mismatch",
        "ip family mismatch",
        "unsupported address family",
        "protocol family unavailable",
        "cannot assign requested address",
        "address family not supported",
        "no suitable address",
        "dual-stack",
        "requiredualstack",
        "ipfamilypolicy",
        "ipfamilies",
    )

    EXCLUSIONS = (
        "networkpolicy",
        "network policy",
        "dns lookup failed",
        "no such host",
        "tls handshake",
        "x509",
        "certificate",
        "failed to create pod sandbox",
        "imagepullbackoff",
        "errimagepull",
    )

    def _parse_timestamp(self, raw: Any):
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event):
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
        )

    def _message(self, event):
        return str(event.get("message") or "")

    def _reason(self, event):
        return str(event.get("reason") or "")

    def _occurrences(self, event):
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _recent_events(self, timeline: Timeline):
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _event_indicates_family_mismatch(self, event):
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        if any(marker in text for marker in self.EXCLUSIONS):
            return False

        return any(marker in text for marker in self.MISMATCH_MARKERS)

    def _pod_ip_families(self, pod_obj):
        families = set()

        pod_ips = pod_obj.get("status", {}).get("podIPs", [])

        for ip_entry in pod_ips:
            ip = str(ip_entry.get("ip", ""))

            if ":" in ip:
                families.add("IPv6")
            elif "." in ip:
                families.add("IPv4")

        pod_ip = pod_obj.get("status", {}).get("podIP")
        if isinstance(pod_ip, str):
            if ":" in pod_ip:
                families.add("IPv6")
            elif "." in pod_ip:
                families.add("IPv4")

        return families

    def _service_families(self, svc):
        spec = svc.get("spec", {}) or {}

        families = set()

        for family in spec.get("ipFamilies", []) or []:
            families.add(str(family))

        cluster_ip = spec.get("clusterIP")
        if isinstance(cluster_ip, str):
            if ":" in cluster_ip:
                families.add("IPv6")
            elif "." in cluster_ip:
                families.add("IPv4")

        for ip in spec.get("clusterIPs", []) or []:
            if ":" in str(ip):
                families.add("IPv6")
            elif "." in str(ip):
                families.add("IPv4")

        return families

    def _endpointslice_families(self, slice_obj):
        families = set()

        address_type = str(slice_obj.get("addressType", ""))

        if address_type:
            families.add(address_type)

        return families

    def _service_mismatch_signals(self, context):
        signals = []
        object_evidence = {}

        services = context.get("objects", {}).get("service", {})
        endpoint_slices = context.get("objects", {}).get(
            "endpointslice",
            {},
        )

        for svc_name, svc in services.items():

            svc_families = self._service_families(svc)

            if not svc_families:
                continue

            namespace = svc.get(
                "metadata",
                {},
            ).get(
                "namespace",
                "default",
            )

            service_slices = [
                s
                for s in endpoint_slices.values()
                if (s.get("metadata", {}).get("namespace", "default") == namespace)
                and (
                    s.get("metadata", {})
                    .get("labels", {})
                    .get("kubernetes.io/service-name")
                    == svc_name
                )
            ]

            for eps in service_slices:

                eps_families = self._endpointslice_families(eps)

                if (
                    svc_families
                    and eps_families
                    and svc_families.isdisjoint(eps_families)
                ):
                    signal = (
                        f"Service {svc_name} "
                        f"families={sorted(svc_families)} "
                        f"EndpointSlice families={sorted(eps_families)}"
                    )

                    signals.append(signal)

                    object_evidence[f"service:{svc_name}"] = [signal]

        return signals, object_evidence

    def _pod_service_family_mismatch(
        self,
        pod,
        context,
    ):
        pod_families = self._pod_ip_families(pod)

        if not pod_families:
            return None

        services = context.get(
            "objects",
            {},
        ).get(
            "service",
            {},
        )

        for svc_name, svc in services.items():

            svc_families = self._service_families(svc)

            if svc_families and pod_families and svc_families.isdisjoint(pod_families):
                return (
                    svc_name,
                    pod_families,
                    svc_families,
                )

        return None

    def _best_candidate(
        self,
        pod,
        timeline,
        context,
    ):
        recent = self._recent_events(timeline)

        mismatch_events = [
            e for e in recent if self._event_indicates_family_mismatch(e)
        ]

        signals, object_evidence = self._service_mismatch_signals(context)

        pod_service_mismatch = self._pod_service_family_mismatch(
            pod,
            context,
        )

        if not mismatch_events and not signals and pod_service_mismatch is None:
            return None

        return {
            "events": mismatch_events,
            "signals": signals,
            "object_evidence": object_evidence,
            "pod_service_mismatch": (pod_service_mismatch),
        }

    def matches(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        return (
            isinstance(
                timeline,
                Timeline,
            )
            and self._best_candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("DualStackIPFamilyMismatch explain() called without match")

        pod_name = pod.get(
            "metadata",
            {},
        ).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get(
            "metadata",
            {},
        ).get(
            "namespace",
            "default",
        )

        evidence = [
            "Detected IPv4/IPv6 family incompatibility in the workload networking path",
        ]

        object_evidence = dict(candidate["object_evidence"])

        if candidate["pod_service_mismatch"]:
            (
                svc_name,
                pod_families,
                svc_families,
            ) = candidate["pod_service_mismatch"]

            msg = (
                f"Pod families={sorted(pod_families)} "
                f"Service {svc_name} families={sorted(svc_families)}"
            )

            evidence.append(msg)

            object_evidence[f"pod:{pod_name}"] = [msg]

        if candidate["events"]:
            evidence.append(self._message(candidate["events"][-1]))

        evidence.extend(candidate["signals"])

        confidence = 0.92

        if candidate["events"] and candidate["signals"]:
            confidence = 0.99
        elif candidate["signals"]:
            confidence = 0.97
        elif candidate["events"]:
            confidence = 0.95

        chain = CausalChain(
            causes=[
                Cause(
                    code="DUALSTACK_NETWORKING_ENABLED",
                    message=(
                        "IPv4 and IPv6 families are expected "
                        "within the workload networking path"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="IP_FAMILY_MISMATCH",
                    message=(
                        "Network components disagree on the "
                        "required IP address family"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SERVICE_CONNECTIVITY_FAILURE",
                    message=(
                        "Traffic cannot be delivered because "
                        "address families are incompatible"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "IPv4/IPv6 dual-stack IP family mismatch is preventing workload connectivity"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v)) for k, v in object_evidence.items()
            },
            "likely_causes": [
                "Service ipFamilies configuration does not match endpoint address families",
                "EndpointSlice addressType differs from Service IP family",
                "RequireDualStack policy is not satisfied",
                "Pods were assigned only one address family in a dual-stack deployment",
                "CNI plugin advertises only IPv4 or only IPv6 addresses",
                "Cluster dual-stack migration left Services and workloads on different families",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get svc -A -o yaml | grep ipFamilies -A5",
                "kubectl get endpointslices.discovery.k8s.io -A",
                "kubectl get pods -A -o wide",
                "Verify Service ipFamilyPolicy and ipFamilies settings",
                "Verify EndpointSlice addressType values",
                "Verify CNI dual-stack support and assigned pod addresses",
            ],
        }
