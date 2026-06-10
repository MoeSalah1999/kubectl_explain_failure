from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class MTUMismatchRule(FailureRule):
    """
    Detects network failures caused by MTU mismatch between
    pod network, overlay network, node interfaces, VPN links,
    or physical network paths.

    Real-world behavior:

    - VXLAN/Geneve/WireGuard overhead reduces usable MTU
    - Nodes configured with inconsistent MTU values
    - CNI MTU larger than underlay network MTU
    - PMTU discovery blocked by firewalls
    - Jumbo frames enabled on only part of the path

    Typical symptoms:

    - TLS handshakes timeout
    - Large HTTP requests fail
    - Small packets succeed
    - PMTU discovery errors
    - Fragmentation-needed ICMP messages
    """

    name = "MTUMismatch"
    category = "Networking"

    severity = "High"
    priority = 70

    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "daemonset",
            "pod",
        ],
    }

    blocks = [
        "NetworkIntermittentPacketLoss",
    ]

    WINDOW_MINUTES = 30

    MTU_MARKERS = (
        "mtu",
        "mtu mismatch",
        "invalid mtu",
        "fragmentation needed",
        "frag needed",
        "packet too big",
        "message too long",
        "icmp frag needed",
        "path mtu",
        "pmtu",
        "pmtud",
        "cannot fragment",
        "df set",
        "needs fragmentation",
        "mtu exceeded",
        "exceeds mtu",
        "frame too large",
        "oversized packet",
        "wireguard mtu",
        "vxlan mtu",
        "geneve mtu",
        "ipip mtu",
        "mss clamping",
        "tcp mss",
    )

    CNI_IDENTIFIERS = (
        "calico",
        "cilium",
        "flannel",
        "antrea",
        "weave",
        "aws-node",
        "azure-cni",
        "ovn",
        "kube-router",
    )

    WORKLOAD_FAILURE_MARKERS = (
        "i/o timeout",
        "context deadline exceeded",
        "tls handshake timeout",
        "connection reset by peer",
        "upstream request timeout",
        "transport: error while dialing",
        "dial tcp",
        "eof",
    )

    RECOVERY_MARKERS = (
        "mtu updated",
        "mtu corrected",
        "network reconfigured",
        "interface recreated",
        "cni reloaded",
    )

    EXCLUDED_MARKERS = (
        "dns",
        "nxdomain",
        "certificate",
        "x509",
        "iptables",
        "conntrack",
        "imagepull",
        "unauthorized",
        "forbidden",
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
        return str(event.get("reason") or "").lower()

    def _recent_events(self, timeline):
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _has_mtu_marker(self, message: str) -> bool:
        lowered = message.lower()
        return any(m in lowered for m in self.MTU_MARKERS)

    def _is_excluded(self, message: str) -> bool:
        lowered = message.lower()
        return any(m in lowered for m in self.EXCLUDED_MARKERS)

    def _is_mtu_failure(self, event: dict[str, Any]) -> bool:
        message = self._message(event)

        if self._is_excluded(message):
            return False

        return self._has_mtu_marker(message)

    def _is_workload_failure(self, event: dict[str, Any]) -> bool:
        lowered = self._message(event).lower()

        return any(marker in lowered for marker in self.WORKLOAD_FAILURE_MARKERS)

    def _is_recovery(self, event):
        lowered = self._message(event).lower()

        return any(marker in lowered for marker in self.RECOVERY_MARKERS)

    def _recovered_after(
        self,
        timeline,
        latest_failure_time,
    ):
        for event in timeline.events:
            if not self._is_recovery(event):
                continue

            ts = self._event_time(event)

            if latest_failure_time is None or ts is None or ts >= latest_failure_time:
                return True

        return False

    def _find_candidate(
        self,
        pod,
        timeline,
        context,
    ):
        recent = self._recent_events(timeline)

        mtu_events = [e for e in recent if self._is_mtu_failure(e)]

        if not mtu_events:
            return None

        workload_events = [e for e in recent if self._is_workload_failure(e)]

        latest_failure = max(
            (self._event_time(e) for e in mtu_events),
            default=None,
        )

        if self._recovered_after(
            timeline,
            latest_failure,
        ):
            return None

        phase = get_pod_phase(pod)

        if phase == "Running" and not workload_events:
            return None

        duration = timeline.duration_between(
            lambda e: self._is_mtu_failure(e) or self._is_workload_failure(e)
        )

        return {
            "mtu_events": mtu_events,
            "workload_events": workload_events,
            "duration": duration,
        }

    def matches(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return False

        return (
            self._find_candidate(
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

        candidate = self._find_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("MTUMismatch explain() called without match")

        latest = candidate["mtu_events"][-1]

        latest_message = self._message(latest)

        chain = CausalChain(
            causes=[
                Cause(
                    code="NETWORK_PATH_MTU_MISMATCH",
                    message=(
                        "Network path MTU is smaller than the packet size being transmitted"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="PACKET_FRAGMENTATION_FAILURE",
                    message=(
                        "Packets cannot traverse the path because fragmentation or PMTU discovery is failing"
                    ),
                    role="infrastructure_symptom",
                ),
                Cause(
                    code="APPLICATION_CONNECTIVITY_FAILURE",
                    message=(
                        "Application traffic fails when packet size exceeds path MTU"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "MTU-related networking failures detected",
            f"Latest MTU failure message: {latest_message}",
            "No MTU recovery event observed after the latest failure",
        ]

        if candidate["duration"]:
            evidence.append(
                f"MTU-related failures persisted for {candidate['duration']/60:.1f} minutes"
            )

        confidence = 0.95

        return {
            "root_cause": ("Network MTU mismatch is causing packet delivery failures"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "likely_causes": [
                "VXLAN overhead not accounted for in configured MTU",
                "WireGuard tunnel MTU larger than underlay path MTU",
                "Calico or Cilium MTU configured incorrectly",
                "Jumbo frames enabled on only part of the network path",
                "PMTU discovery blocked by firewall rules",
                "VPN or transit gateway path MTU lower than cluster MTU",
            ],
            "suggested_checks": [
                "kubectl describe pod <pod>",
                "kubectl get events --all-namespaces | grep -i mtu",
                "kubectl logs -n kube-system <cni-pod>",
                "ip link show",
                "tracepath <destination>",
                "ping -M do -s 1472 <destination>",
                "Check CNI MTU configuration against underlay MTU",
                "Verify VXLAN/Geneve/WireGuard encapsulation overhead",
            ],
        }
