from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ConntrackTableFullRule(FailureRule):
    """
    Detects workload connectivity failures whose root cause is the Linux
    netfilter connection-tracking table filling up on the Pod's node.

    Real-world behavior:
    - every NATed or stateful flow on a Kubernetes node consumes a conntrack
      entry in the kernel nf_conntrack table
    - when the table reaches nf_conntrack_max, the kernel logs
      "nf_conntrack: table full, dropping packet" and silently drops NEW
      connection attempts; existing flows may continue briefly
    - symptoms are intermittent and node-local: many Pods on the same node
      see dial timeouts, i/o timeouts, or connection resets at the same time
      while Pods on other nodes remain healthy
    - common on busy nodes with high connection churn (short-lived HTTP/gRPC,
      aggressive health probes, NodePort/LB ingress, kube-proxy SNAT, DNS UDP
      storms, monitoring port scans, or hairpin NAT)
    - typical signals:
        * kernel / node logs or surfaced events mention "conntrack table full",
          "nf_conntrack: table full", or nf_conntrack_max exhaustion
        * node-problem-detector, monitoring agents, or kubelet-adjacent logs
          report connection-tracking saturation on a specific node
        * workload Pods on that node emit repeated timeout / dial failures to
          ClusterIP Services, NodePorts, or external endpoints without DNS or
          CNI sandbox errors
        * the issue clears temporarily when old flows expire or the node is
          drained, then returns under the same traffic pattern

    Distinction from related rules:
    - KubeProxyUnavailable / KubeProxySyncFailure: kube-proxy process or sync
      loop failure, not kernel conntrack exhaustion
    - DNSResolutionFailure: authoritative NXDOMAIN / lookup errors, not packet
      drops caused by a full conntrack table
    - NodeNetworkUnavailable: explicit NetworkUnavailable node condition during
      bootstrap, not mid-flight conntrack saturation
    - CNIPluginFailure: sandbox creation failure, not established-node routing

    Exclusions:
    - pure DNS misconfiguration (no such host / NXDOMAIN)
    - CNI / IPAM sandbox failures
    - NetworkPolicy deliberate drops
    - kube-proxy crash or sync-loop errors without conntrack evidence
    - certificate / TLS handshake failures
    """

    name = "ConntrackTableFull"
    category = "Networking"
    severity = "High"
    priority = 69
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "pod",
        ],
    }

    blocks = [
        "DNSResolutionFailure",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
        "NetworkIntermittentPacketLoss",
        "IntermittentNetworkFlapping",
    ]

    WINDOW_MINUTES = 20

    # Direct conntrack saturation markers (kernel, node agents, surfaced logs)
    CONNTRACK_SIGNAL_MARKERS = (
        "nf_conntrack: table full",
        "nf_conntrack table full",
        "conntrack table full",
        "conntrack: table full",
        "conntrack buckets are full",
        "connection tracking table full",
        "connection-tracking table full",
        "ip_conntrack table full",
        "reached connection tracking limit",
        "exceeded nf_conntrack_max",
        "nf_conntrack_max exceeded",
        "nf_conntrack count",
        "conntrack count exceeded",
        "conntrack limit reached",
        "conntrack full",
        "xt_connlimit",
    )

    # Partial markers that require an additional conntrack keyword in the text
    CONNTRACK_PARTIAL_MARKERS = (
        "dropping packet",
        "packet drop",
        "connection tracking",
        "nf_conntrack",
        "ip_conntrack",
    )

    # Components that commonly surface node/kernel networking pressure
    NODE_INFRA_COMPONENTS = frozenset(
        {
            "kubelet",
            "node-problem-detector",
            "kernel",
            "system",
            "node-exporter",
            "node_exporter",
            "monitoring",
            "prometheus",
            "alertmanager",
            "nodeagent",
            "node-agent",
        }
    )

    CONNTRACK_EVENT_REASONS = frozenset(
        {
            "conntracktablefull",
            "conntrackfull",
            "nfconntracktablefull",
            "nodecondition",
            "kerneloom",
            "warning",
            "failed",
        }
    )

    # Workload-side symptoms consistent with dropped NEW connections
    WORKLOAD_CONNECTIVITY_MARKERS = (
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "io timeout",
        "context deadline exceeded",
        "connection timed out",
        "connection reset by peer",
        "read: connection reset",
        "write: broken pipe",
        "broken pipe",
        "no route to host",
        "network is unreachable",
        "eof",
        "upstream connect error",
        "upstream request timeout",
        "transport: error while dialing",
        "temporary failure",
        "503",
        "502",
        "504",
    )

    CLUSTER_TARGET_MARKERS = (
        "kubernetes.default",
        "svc.cluster.local",
        ".svc.",
        "cluster.local",
        "10.96.",
        "10.0.0.",
        "172.20.",
        "172.16.",
        "192.168.0.",
    )

    EXCLUDED_MARKERS = (
        "no such host",
        "nxdomain",
        "dns lookup",
        "cannot resolve",
        "failed to resolve",
        "lookup ",
        "name or service not known",
        "cni",
        "ipam",
        "failed to create pod sandbox",
        "failedcreatepodsandbox",
        "networkpolicy",
        "network policy",
        "denied by",
        "x509:",
        "certificate",
        "tls handshake",
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "failed to sync iptables",
        "failed to sync proxy rules",
        "syncproxyrules",
        "crashloopbackoff",
        "back-off restarting failed container",
    )

    RECOVERY_MARKERS = (
        "conntrack table recovered",
        "conntrack usage normalized",
        "nf_conntrack below threshold",
        "connection tracking pressure cleared",
    )

    # ------------------------------------------------------------------ #
    # Timestamp helpers                                                    #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    # Basic accessors                                                      #
    # ------------------------------------------------------------------ #

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _node_for_pod(self, pod: dict[str, Any]) -> str | None:
        return pod.get("spec", {}).get("nodeName") or None

    def _is_excluded(self, message: str) -> bool:
        lowered = message.lower()
        return any(marker in lowered for marker in self.EXCLUDED_MARKERS)

    def _targets_current_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True
        kind = str(involved.get("kind") or "").lower()
        if kind and kind not in {"pod", ""}:
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

    def _event_targets_node(self, event: dict[str, Any], node_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if (
                str(involved.get("kind") or "").lower() == "node"
                and involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True
        lowered = self._message(event).lower()
        return node_name.lower() in lowered

    # ------------------------------------------------------------------ #
    # Conntrack signal classification                                      #
    # ------------------------------------------------------------------ #

    def _has_conntrack_marker(self, message: str) -> bool:
        lowered = message.lower()
        if any(marker in lowered for marker in self.CONNTRACK_SIGNAL_MARKERS):
            return True
        if "conntrack" not in lowered and "nf_conntrack" not in lowered:
            return False
        return any(marker in lowered for marker in self.CONNTRACK_PARTIAL_MARKERS)

    def _is_conntrack_signal_event(
        self,
        event: dict[str, Any],
        node_name: str | None,
    ) -> bool:
        message = self._message(event)
        if not self._has_conntrack_marker(message):
            return False

        reason = self._reason(event).lower()
        component = self._source_component(event)

        involved = event.get("involvedObject", {})
        if node_name and isinstance(involved, dict):
            involved_kind = str(involved.get("kind") or "").lower()
            involved_name = involved.get("name")
            if involved_kind == "node" and involved_name and involved_name != node_name:
                return False
            if (
                involved_kind == "pod"
                and involved.get("nodeName")
                and involved.get("nodeName") != node_name
            ):
                return False

        if reason in self.CONNTRACK_EVENT_REASONS:
            return True

        if component in self.NODE_INFRA_COMPONENTS:
            return True

        lowered = message.lower()
        if any(marker in lowered for marker in self.CONNTRACK_SIGNAL_MARKERS):
            return True

        return "conntrack" in lowered or "nf_conntrack" in lowered

    def _is_conntrack_recovery_event(self, event: dict[str, Any]) -> bool:
        lowered = self._message(event).lower()
        return any(marker in lowered for marker in self.RECOVERY_MARKERS)

    # ------------------------------------------------------------------ #
    # Workload symptom classification                                      #
    # ------------------------------------------------------------------ #

    def _is_workload_connectivity_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False

        message = self._message(event)
        if self._is_excluded(message):
            return False

        lowered = message.lower()
        has_connectivity_failure = any(
            marker in lowered for marker in self.WORKLOAD_CONNECTIVITY_MARKERS
        )
        if not has_connectivity_failure:
            return False

        has_cluster_target = any(
            marker in lowered for marker in self.CLUSTER_TARGET_MARKERS
        )
        # Accept generic dial/tcp failures even without an explicit service name.
        return has_cluster_target or "dial tcp" in lowered or "i/o timeout" in lowered

    # ------------------------------------------------------------------ #
    # Node object corroboration                                            #
    # ------------------------------------------------------------------ #

    def _node_object_signals(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[str]:
        if not node_name:
            return []

        signals: list[str] = []
        nodes = context.get("objects", {}).get("node", {}) or {}
        node = nodes.get(node_name)
        if not isinstance(node, dict):
            return signals

        for cond in node.get("status", {}).get("conditions", []) or []:
            message = str(cond.get("message") or "")
            reason = str(cond.get("reason") or "")
            text = f"{reason} {message}".lower()
            if self._has_conntrack_marker(text):
                cond_type = cond.get("type", "Unknown")
                signals.append(
                    f"Node condition {cond_type} references conntrack saturation: {message or reason}"
                )

        return signals

    def _peer_pod_signals_on_node(
        self,
        context: dict[str, Any],
        node_name: str | None,
        current_pod: dict[str, Any],
    ) -> list[str]:
        if not node_name:
            return []

        current_name = current_pod.get("metadata", {}).get("name")
        current_namespace = current_pod.get("metadata", {}).get("namespace")
        signals: list[str] = []
        pods = context.get("objects", {}).get("pod", {}) or {}

        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue
            if pod_obj.get("spec", {}).get("nodeName") != node_name:
                continue
            pod_name = pod_obj.get("metadata", {}).get("name")
            pod_namespace = pod_obj.get("metadata", {}).get("namespace")
            if pod_name == current_name and pod_namespace == current_namespace:
                continue
            phase = pod_obj.get("status", {}).get("phase")
            if phase not in {"Running", "Pending"}:
                continue
            signals.append(
                f"Additional workload Pod {pod_namespace}/{pod_name} is scheduled on the same node"
            )
            if len(signals) >= 2:
                break

        return signals

    # ------------------------------------------------------------------ #
    # Recovery guard                                                       #
    # ------------------------------------------------------------------ #

    def _conntrack_recovered_after(
        self,
        timeline: Timeline,
        latest_failure_at: datetime | None,
        node_name: str | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_conntrack_recovery_event(event):
                continue
            if node_name and not self._event_targets_node(event, node_name):
                continue
            event_at = self._event_time(event)
            if (
                latest_failure_at is None
                or event_at is None
                or event_at >= latest_failure_at
            ):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Candidate assembly                                                   #
    # ------------------------------------------------------------------ #

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        recent_events = self._ordered_recent_events(timeline)
        node_name = self._node_for_pod(pod)

        workload_events = [
            event
            for event in recent_events
            if self._is_workload_connectivity_failure(event, pod)
        ]
        if not workload_events:
            return None

        conntrack_events = [
            event
            for event in recent_events
            if self._is_conntrack_signal_event(event, node_name)
        ]
        node_signals = self._node_object_signals(context, node_name)
        peer_signals = self._peer_pod_signals_on_node(context, node_name, pod)

        if not conntrack_events and not node_signals:
            return None

        latest_conntrack_at = (
            self._event_time(conntrack_events[-1]) if conntrack_events else None
        )
        if conntrack_events and self._conntrack_recovered_after(
            timeline,
            latest_conntrack_at,
            node_name,
        ):
            return None

        workload_occurrences = sum(
            self._occurrences(event) for event in workload_events
        )
        conntrack_occurrences = sum(
            self._occurrences(event) for event in conntrack_events
        )
        duration_seconds = timeline.duration_between(
            lambda event: self._is_workload_connectivity_failure(event, pod)
            or self._is_conntrack_signal_event(event, node_name)
        )

        return {
            "node_name": node_name,
            "workload_events": workload_events,
            "conntrack_events": conntrack_events,
            "node_signals": node_signals,
            "peer_signals": peer_signals,
            "workload_occurrences": workload_occurrences,
            "conntrack_occurrences": conntrack_occurrences,
            "duration_seconds": duration_seconds,
        }

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ConntrackTableFull requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("ConntrackTableFull explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = candidate["node_name"]
        workload_events = candidate["workload_events"]
        conntrack_events = candidate["conntrack_events"]
        node_signals = candidate["node_signals"]
        peer_signals = candidate["peer_signals"]
        workload_occurrences = candidate["workload_occurrences"]
        conntrack_occurrences = candidate["conntrack_occurrences"]
        duration_seconds = candidate["duration_seconds"]

        representative_workload = self._message(workload_events[-1])
        representative_conntrack = (
            self._message(conntrack_events[-1]) if conntrack_events else ""
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_CONNTRACK_CAPACITY_EXHAUSTED",
                    message=(
                        "The node's netfilter connection-tracking table reached "
                        "nf_conntrack_max and began dropping new flows"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="NEW_CONNECTIONS_DROPPED",
                    message=(
                        "Stateful/NATed packets for new connections are dropped "
                        "at the node, causing intermittent reachability failures"
                    ),
                    role="network_mechanism",
                ),
                Cause(
                    code="WORKLOAD_CONNECTIVITY_DEGRADED",
                    message="Pod observes dial timeouts and connection failures to dependencies",
                    role="workload_symptom",
                ),
            ]
        )

        evidence: list[str] = [
            f"Pod {namespace}/{pod_name} shows node-local connectivity degradation",
            f"Representative workload failure: {representative_workload}",
            (
                f"Observed {workload_occurrences} workload connectivity failure "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            ),
            "Conntrack saturation is evidenced separately from the workload symptom",
        ]
        evidence.extend(node_signals)
        evidence.extend(peer_signals)
        if representative_conntrack:
            evidence.append(
                f"Representative conntrack saturation signal: {representative_conntrack}"
            )
        if conntrack_occurrences:
            evidence.append(
                f"Observed {conntrack_occurrences} conntrack saturation signal "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            )
        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")
        if duration_seconds:
            evidence.append(
                f"Conntrack and workload failure signals persisted for "
                f"{duration_seconds / 60:.1f} minutes"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [representative_workload],
        }
        if node_name:
            node_evidence = ["Node connection-tracking table is saturated"]
            if representative_conntrack:
                node_evidence.append(representative_conntrack)
            object_evidence[f"node:{node_name}"] = node_evidence

        confidence = 0.88
        if node_signals and conntrack_events:
            confidence = 0.97
        elif node_signals or peer_signals:
            confidence = 0.94
        elif conntrack_events:
            confidence = 0.91

        return {
            "root_cause": (
                "Node netfilter conntrack table is full and new connections are being dropped"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "nf_conntrack_max is too low for the node's connection churn",
                "High short-lived TCP/UDP traffic from many Pods on the same node",
                "kube-proxy SNAT, NodePort, or hairpin NAT multiplying tracked flows",
                "Aggressive health probes or monitoring scans opening many parallel connections",
                "Long-lived stale conntrack entries not expiring quickly under the current sysctl tuning",
            ],
            "suggested_checks": [
                *(
                    [
                        f"kubectl describe node {node_name}",
                        f"ssh {node_name} 'cat /proc/sys/net/netfilter/nf_conntrack_count; cat /proc/sys/net/netfilter/nf_conntrack_max'",
                        f"ssh {node_name} 'dmesg | grep -i conntrack | tail -20'",
                        f"ssh {node_name} 'conntrack -S 2>/dev/null || true'",
                    ]
                    if node_name
                    else [
                        "Inspect affected node kernel logs for nf_conntrack table-full messages",
                        "Compare nf_conntrack_count against nf_conntrack_max on busy nodes",
                    ]
                ),
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get pods -A -o wide --field-selector spec.nodeName=<node> | head",
                "Review connection-heavy workloads, NodePort exposure, and probe intervals on the node",
                "Consider raising nf_conntrack_max and reducing connection churn or spreading Pods across nodes",
            ],
        }
