from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class EBPFDataplaneProgramFailureRule(FailureRule):
    """
    Detects pod networking failures caused by eBPF dataplane program load,
    attach, verifier, or map failures on the assigned node.

    Real-world behavior:
    - CNI plugins and node agents that use an eBPF dataplane (Cilium, Calico
      Felix in eBPF mode, Antrea with eBPF features, some cloud CNIs) compile
      and attach TC/XDP/cgroup BPF programs and populate BPF maps for routing,
      policy enforcement, SNAT, and service load-balancing
    - when program load fails (verifier rejection, memlock limits, missing
      kernel BTF), attach fails (TC hook conflict, stale qdisc), or a BPF map
      fills up, the agent cannot program the dataplane for new or changed
      endpoints
    - Pending Pods may fail sandbox creation with CNIPluginFailure /
      FailedCreatePodSandBox messages referencing bpf/ebpf
    - Running Pods on the same node may see connectivity loss, policy bypass,
      or stale routing when endpoint regeneration fails even though the agent
      process remains alive
    - typical signals:
        * cilium-agent / calico-node / antrea-agent events or logs mention
          "bpf verifier", "failed to load bpf", "bpf map is full",
          "endpoint regeneration failed", "tc attach", or "RLIMIT_MEMLOCK"
        * workload Pod events show dial/timeouts while the node agent reports
          independent eBPF programming failures
        * node NetworkUnavailable=True may appear when the dataplane cannot be
          restored

    Distinction from related rules:
    - IPTablesRestoreFailure: iptables-restore / xtables lock errors, not BPF
    - CNIPluginFailure: generic CNI sandbox failure without eBPF evidence
    - KubeProxyUnavailable / KubeProxySyncFailure: kube-proxy iptables/ipvs
      sync failures in non-eBPF dataplane clusters
    - ConntrackTableFull: kernel nf_conntrack saturation, not BPF program load

    Exclusions:
    - iptables-restore or xtables lock failures
    - IPAM / sandbox IP allocation failures
    - missing CNI config file errors
    - container-runtime socket unavailability
    - pure DNS NXDOMAIN or certificate errors
    """

    name = "EBPFDataplaneProgramFailure"
    category = "Networking"
    severity = "High"
    priority = 68
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline", "node", "node_conditions"],
        "optional_objects": [
            "node",
            "pod",
            "daemonset",
        ],
    }

    blocks = [
        "CNIPluginFailure",
        "DNSResolutionFailure",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
        "NetworkIntermittentPacketLoss",
    ]

    WINDOW_MINUTES = 30
    MIN_OCCURRENCES_WITHOUT_NODE_CONDITION = 2

    # ------------------------------------------------------------------ #
    # eBPF failure markers                                                 #
    # ------------------------------------------------------------------ #

    EBPF_FAILURE_MARKERS = (
        "bpf verifier",
        "verifier rejected",
        "verifier log",
        "failed to load bpf",
        "failed to load ebpf",
        "bpf prog load",
        "bpf_prog_load",
        "bpf object load",
        "failed to attach bpf",
        "attach bpf program",
        "bpf attach",
        "failed to pin bpf",
        "bpf pin",
        "bpf map",
        "map is full",
        "map resize failed",
        "bpf filesystem",
        "bpf fs",
        "tc attach",
        "xdp attach",
        "cgroup bpf",
        "ebpf dataplane",
        "ebpf program",
        "datapath program",
        "datapath agent",
        "endpoint regeneration failed",
        "unable to regenerate endpoint",
        "failed to regenerate endpoint",
        "failed to compile bpf",
        "bpf compilation",
        "jit compilation failed",
        "rlimit_memlock",
        "rlimit memlock",
        "cannot allocate bpf",
        "bpf template",
        "failed to update bpf",
        "bpf programs not loaded",
        "failed to apply bpf programs",
        "bpf interface",
        "ebpf enforcement",
        "load bpf object",
        "reload bpf",
    )

    EBPF_PARTIAL_MARKERS = (
        "ebpf",
        " bpf ",
        "bpf:",
        "bpf,",
        "bpf.",
    )

    # CNI / node agents that program an eBPF dataplane
    EBPF_AGENT_IDENTIFIERS = (
        "cilium",
        "cilium-agent",
        "calico-node",
        "felix",
        "antrea-agent",
        "antrea",
        "aws-node",
        "aws-node-agent",
        "cni-node",
        "node-agent",
    )

    EBPF_AGENT_COMPONENTS = frozenset(
        {
            "cilium-agent",
            "cilium",
            "calico-node",
            "felix",
            "antrea-agent",
            "antrea",
            "aws-node",
            "node-agent",
        }
    )

    SANDBOX_REASONS = frozenset(
        {
            "failedcreatepodsandbox",
            "cnipluginfailure",
            "networknotready",
            "failed",
            "unhealthy",
            "backoff",
        }
    )

    AGENT_FAILURE_REASONS = frozenset(
        {
            "unhealthy",
            "failed",
            "backoff",
            "failedcreatepodsandbox",
            "cnipluginfailure",
            "warning",
        }
    )

    SUCCESS_REASONS = frozenset(
        {
            "Started",
            "Created",
            "AddedInterface",
            "SandboxChanged",
            "EndpointRegenerationComplete",
            "Ready",
        }
    )

    WORKLOAD_CONNECTIVITY_MARKERS = (
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "connection timed out",
        "connection reset by peer",
        "no route to host",
        "network is unreachable",
        "upstream connect error",
        "upstream request timeout",
        "transport: error while dialing",
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
    )

    EXCLUDED_MARKERS = (
        "iptables-restore",
        "ip6tables-restore",
        "xtables lock",
        "xtables-lock",
        "no available ip",
        "no more ips",
        "ipam exhausted",
        "address pool exhausted",
        "failed to allocate ip",
        "failed to assign an ip",
        "cni config uninitialized",
        "no networks found in /etc/cni/net.d",
        "failed to load cni config",
        "network plugin is not ready",
        "container runtime is down",
        "failed to connect to container runtime",
        "containerd.sock",
        "cri-o.sock",
        "imagepullbackoff",
        "errimagepull",
        "image pull",
        "unauthorized",
        "forbidden",
        "certificateexpired",
        "x509:",
        "no such host",
        "nxdomain",
        "cannot resolve",
        "failed to resolve",
        "nf_conntrack: table full",
        "conntrack table full",
    )

    RECOVERY_MARKERS = (
        "bpf programs loaded",
        "bpf programs reloaded",
        "endpoint regeneration complete",
        "datapath reloaded",
        "ebpf dataplane restored",
        "successfully attached bpf",
    )

    # ------------------------------------------------------------------ #
    # Timeline helpers                                                     #
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

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        indexed = list(enumerate(events))
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

    def _recent_ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return self._ordered_events(timeline.events_within_window(self.WINDOW_MINUTES))

    # ------------------------------------------------------------------ #
    # Basic accessors                                                      #
    # ------------------------------------------------------------------ #

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "").lower()

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _source_host(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("host") or "").lower()
        return ""

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _involved_kind(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("kind") or "").lower()

    def _involved_name(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("name") or "")

    def _involved_namespace(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("namespace") or "")

    def _node_for_pod(self, pod: dict[str, Any]) -> str:
        return str(pod.get("spec", {}).get("nodeName") or "")

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{k}={v}".lower() for k, v in labels.items())

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    # ------------------------------------------------------------------ #
    # Marker and exclusion logic                                           #
    # ------------------------------------------------------------------ #

    def _has_ebpf_marker(self, message: str) -> bool:
        lowered = message.lower()
        if any(marker in lowered for marker in self.EBPF_FAILURE_MARKERS):
            return True
        if not any(marker in lowered for marker in self.EBPF_PARTIAL_MARKERS):
            return False
        return "program" in lowered or "map" in lowered or "attach" in lowered

    def _is_excluded(self, message: str) -> bool:
        lowered = message.lower()
        return any(marker in lowered for marker in self.EXCLUDED_MARKERS)

    def _targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved_kind = self._involved_kind(event)
        if involved_kind and involved_kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")
        involved_name = self._involved_name(event)
        involved_ns = self._involved_namespace(event)

        if pod_name and involved_name and involved_name != pod_name:
            return False
        if namespace and involved_ns and involved_ns != namespace:
            return False
        return True

    def _event_on_node(self, event: dict[str, Any], node_name: str) -> bool:
        if not node_name:
            return True

        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if (
                str(involved.get("kind") or "").lower() == "node"
                and involved.get("name")
                and involved.get("name") != node_name
            ):
                return False
            if involved.get("nodeName") and involved.get("nodeName") != node_name:
                return False

        host = self._source_host(event)
        if host and node_name.lower() not in host:
            return False

        return node_name.lower() in self._message(event).lower() or not host

    def _involves_ebpf_agent(self, event: dict[str, Any]) -> bool:
        component = self._source_component(event)
        if component in self.EBPF_AGENT_COMPONENTS:
            return True

        involved_text = " ".join(
            str(v).lower()
            for v in (
                self._involved_name(event),
                self._involved_namespace(event),
                component,
                self._message(event),
            )
            if v
        )
        return any(
            identifier in involved_text for identifier in self.EBPF_AGENT_IDENTIFIERS
        )

    # ------------------------------------------------------------------ #
    # Event classification                                                 #
    # ------------------------------------------------------------------ #

    def _is_ebpf_failure_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        node_name: str,
    ) -> bool:
        message = self._message(event)
        if not self._has_ebpf_marker(message):
            return False
        if self._is_excluded(message):
            return False
        if not self._event_on_node(event, node_name):
            return False

        reason = self._reason(event)

        if reason in self.SANDBOX_REASONS and self._targets_pod(event, pod):
            return True

        if reason in self.AGENT_FAILURE_REASONS and self._involves_ebpf_agent(event):
            return True

        if self._involves_ebpf_agent(event) and reason in {
            "failed",
            "unhealthy",
            "warning",
            "backoff",
        }:
            return True

        return False

    def _is_workload_connectivity_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_pod(event, pod):
            return False

        message = self._message(event)
        if self._is_excluded(message):
            return False

        lowered = message.lower()
        has_failure = any(
            marker in lowered for marker in self.WORKLOAD_CONNECTIVITY_MARKERS
        )
        if not has_failure:
            return False

        has_cluster_target = any(
            marker in lowered for marker in self.CLUSTER_TARGET_MARKERS
        )
        return has_cluster_target or "dial tcp" in lowered or "i/o timeout" in lowered

    def _is_recovery_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        node_name: str,
    ) -> bool:
        reason = str(event.get("reason") or "")
        if reason in self.SUCCESS_REASONS and self._targets_pod(event, pod):
            return True

        lowered = self._message(event).lower()
        if not any(marker in lowered for marker in self.RECOVERY_MARKERS):
            return False
        return self._event_on_node(event, node_name)

    # ------------------------------------------------------------------ #
    # Node / object corroboration                                          #
    # ------------------------------------------------------------------ #

    def _node_network_unavailable(self, context: dict[str, Any]) -> bool:
        node_conditions: dict[str, Any] = context.get("node_conditions") or {}
        value = node_conditions.get("NetworkUnavailable")
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, dict):
            return str(value.get("status", "")).lower() == "true"
        return str(value).lower() in {"true", "yes", "1"}

    def _is_ebpf_agent_object(self, obj: dict[str, Any]) -> bool:
        text = " ".join(
            v.lower()
            for v in (
                self._object_name(obj),
                self._labels_text(obj),
                str(obj.get("metadata", {}).get("generateName") or ""),
            )
            if v
        )
        return any(identifier in text for identifier in self.EBPF_AGENT_IDENTIFIERS)

    def _daemonset_signals(
        self,
        context: dict[str, Any],
        node_name: str,
    ) -> list[str]:
        signals: list[str] = []
        daemonsets = context.get("objects", {}).get("daemonset", {}) or {}

        for ds in daemonsets.values():
            if not isinstance(ds, dict) or not self._is_ebpf_agent_object(ds):
                continue

            ds_name = self._object_name(ds)
            status = ds.get("status", {}) or {}
            unavailable = status.get("numberUnavailable", 0)
            ready = status.get("numberReady", 0)
            desired = status.get("desiredNumberScheduled", 0)

            if unavailable and unavailable > 0:
                signals.append(
                    f"eBPF dataplane DaemonSet '{ds_name}' has "
                    f"{unavailable} unavailable node(s)"
                )
            elif desired > 0 and ready < desired:
                signals.append(
                    f"eBPF dataplane DaemonSet '{ds_name}' has only "
                    f"{ready}/{desired} ready Pods"
                )

        return signals

    def _agent_pod_signals(
        self,
        context: dict[str, Any],
        node_name: str,
    ) -> list[str]:
        if not node_name:
            return []

        signals: list[str] = []
        pods = context.get("objects", {}).get("pod", {}) or {}

        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue
            if not self._is_ebpf_agent_object(pod_obj):
                continue
            if pod_obj.get("spec", {}).get("nodeName") != node_name:
                continue

            agent_name = self._object_name(pod_obj)
            status = pod_obj.get("status", {}) or {}
            phase = status.get("phase", "")

            if phase in {"Failed", "Unknown"}:
                signals.append(f"eBPF agent Pod '{agent_name}' is in phase {phase}")
                continue

            ready = any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in status.get("conditions", []) or []
            )
            if not ready:
                signals.append(f"eBPF agent Pod '{agent_name}' is not Ready")

            for cs in status.get("containerStatuses", []) or []:
                waiting = (cs.get("state", {}) or {}).get("waiting", {}) or {}
                reason = waiting.get("reason", "")
                if reason in {
                    "CrashLoopBackOff",
                    "Error",
                    "RunContainerError",
                    "CreateContainerConfigError",
                }:
                    signals.append(
                        f"eBPF agent Pod '{agent_name}' container waiting reason={reason}"
                    )

            for cs in status.get("containerStatuses", []) or []:
                restarts = cs.get("restartCount", 0)
                if isinstance(restarts, int) and restarts >= 3:
                    signals.append(
                        f"eBPF agent Pod '{agent_name}' has restarted {restarts} time(s)"
                    )

        return signals

    # ------------------------------------------------------------------ #
    # Recovery guard                                                       #
    # ------------------------------------------------------------------ #

    def _recovered_after(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        latest_failure_at: datetime | None,
        node_name: str,
    ) -> bool:
        for event in timeline.events:
            if not self._is_recovery_event(event, pod, node_name):
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

    def _collect_ebpf_events(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        node_name: str,
    ) -> list[dict[str, Any]]:
        return [
            event
            for event in self._recent_ordered_events(timeline)
            if self._is_ebpf_failure_event(event, pod, node_name)
        ]

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        node_name = self._node_for_pod(pod)
        ebpf_events = self._collect_ebpf_events(pod, timeline, node_name)
        if not ebpf_events:
            return None

        has_node_condition = self._node_network_unavailable(context)
        total_occurrences = sum(self._occurrences(event) for event in ebpf_events)
        if (
            not has_node_condition
            and total_occurrences < self.MIN_OCCURRENCES_WITHOUT_NODE_CONDITION
        ):
            return None

        latest_failure_at = self._event_time(ebpf_events[-1])
        if self._recovered_after(pod, timeline, latest_failure_at, node_name):
            return None

        recent_events = self._recent_ordered_events(timeline)
        workload_events = [
            event
            for event in recent_events
            if self._is_workload_connectivity_failure(event, pod)
        ]

        # Pending pods can match on direct sandbox/CNI eBPF failures alone.
        # Running pods need corroborating workload impact unless node condition
        # or agent object degradation is present.
        phase = get_pod_phase(pod)
        ds_signals = self._daemonset_signals(context, node_name)
        agent_signals = self._agent_pod_signals(context, node_name)
        object_signals = ds_signals + agent_signals

        if phase == "Running" and not workload_events:
            if not has_node_condition and not object_signals:
                return None

        workload_occurrences = sum(
            self._occurrences(event) for event in workload_events
        )
        duration_seconds = timeline.duration_between(
            lambda event: self._is_ebpf_failure_event(event, pod, node_name)
            or self._is_workload_connectivity_failure(event, pod)
        )

        return {
            "node_name": node_name,
            "ebpf_events": ebpf_events,
            "workload_events": workload_events,
            "object_signals": object_signals,
            "ds_signals": ds_signals,
            "agent_signals": agent_signals,
            "has_node_condition": has_node_condition,
            "total_occurrences": total_occurrences,
            "workload_occurrences": workload_occurrences,
            "duration_seconds": duration_seconds,
        }

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def matches(self, pod, events, context) -> bool:
        phase = get_pod_phase(pod)
        if phase not in {"Pending", "Running"}:
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline, context) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("EBPFDataplaneProgramFailure requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "EBPFDataplaneProgramFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        phase = get_pod_phase(pod)
        node_name = candidate["node_name"]
        ebpf_events = candidate["ebpf_events"]
        workload_events = candidate["workload_events"]
        object_signals = candidate["object_signals"]
        has_node_condition = candidate["has_node_condition"]
        total_occurrences = candidate["total_occurrences"]
        workload_occurrences = candidate["workload_occurrences"]
        duration_seconds = candidate["duration_seconds"]

        latest = ebpf_events[-1]
        latest_message = self._message(latest).strip()
        latest_reason = str(latest.get("reason") or "CNIPluginFailure")
        representative_workload = (
            self._message(workload_events[-1]) if workload_events else ""
        )

        combined_messages = " ".join(
            self._message(event).lower() for event in ebpf_events
        )
        is_verifier_rejection = any(
            marker in combined_messages
            for marker in ("verifier rejected", "bpf verifier", "verifier log")
        )
        is_map_pressure = any(
            marker in combined_messages
            for marker in ("map is full", "map resize failed", "bpf map")
        )
        is_memlock = any(
            marker in combined_messages
            for marker in ("rlimit_memlock", "rlimit memlock", "cannot allocate bpf")
        )
        is_attach_failure = any(
            marker in combined_messages
            for marker in (
                "tc attach",
                "xdp attach",
                "failed to attach bpf",
                "bpf attach",
            )
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="EBPF_DATAPLANE_PROGRAMMING_FAILED",
                    message=(
                        "The node's eBPF dataplane agent could not load, attach, or "
                        "maintain required BPF programs/maps for pod networking"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ENDPOINT_DATAPLANE_NOT_PROGRAMMED",
                    message=(
                        "Without a healthy eBPF dataplane, endpoint routing, policy, "
                        "or SNAT state is missing or stale on the node"
                    ),
                    role="infrastructure_symptom",
                ),
                Cause(
                    code="POD_NETWORK_IMPACT",
                    message=(
                        "Pod sandbox creation or in-cluster connectivity fails while "
                        "the eBPF dataplane remains broken"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} is {phase} while the node eBPF dataplane is failing",
            (
                f"Observed {total_occurrences} eBPF dataplane failure "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            ),
            f"Latest eBPF dataplane failure reason: {latest_reason}",
            f"Latest eBPF dataplane failure message: {latest_message}",
            "No successful pod network recovery event observed after the latest eBPF failure",
        ]
        evidence.extend(object_signals)

        if node_name:
            evidence.append(f"Pod is assigned to node '{node_name}'")

        if has_node_condition:
            evidence.append(
                f"Node '{node_name or '<unassigned>'}' reports NetworkUnavailable=True"
            )

        if representative_workload:
            evidence.append(
                f"Representative workload connectivity failure: {representative_workload}"
            )
            evidence.append(
                f"Observed {workload_occurrences} workload connectivity failure "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            )

        if is_verifier_rejection:
            evidence.append(
                "BPF verifier rejection detected — compiled program semantics are "
                "invalid for the running kernel"
            )
        if is_map_pressure:
            evidence.append(
                "BPF map pressure detected — dataplane map limits or resize failures "
                "are preventing state programming"
            )
        if is_memlock:
            evidence.append(
                "RLIMIT_MEMLOCK / BPF memory allocation failure detected — the agent "
                "cannot pin required BPF objects"
            )
        if is_attach_failure:
            evidence.append(
                "BPF attach failure detected — TC/XDP/cgroup hook attachment is failing "
                "on the node interface or cgroup path"
            )

        if duration_seconds:
            evidence.append(
                f"eBPF dataplane failure signals persisted for "
                f"{duration_seconds / 60:.1f} minutes"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [
                "Pod networking is blocked or degraded by an eBPF dataplane programming failure",
                latest_message,
            ],
        }
        if node_name:
            node_evidence = [
                "Node eBPF dataplane programming is failing; routing/policy/SNAT state may be absent or stale"
            ]
            if has_node_condition:
                node_evidence.append("Node condition NetworkUnavailable=True")
            object_evidence[f"node:{node_name}"] = node_evidence
        if candidate["ds_signals"]:
            object_evidence["daemonset:ebpf-agent"] = list(candidate["ds_signals"])
        if candidate["agent_signals"]:
            object_evidence.setdefault("pod:ebpf-agent", []).extend(
                candidate["agent_signals"]
            )

        confidence = 0.84
        if has_node_condition and object_signals:
            confidence = 0.97
        elif has_node_condition or (object_signals and workload_events):
            confidence = 0.94
        elif object_signals or workload_events:
            confidence = 0.91
        elif total_occurrences >= 3:
            confidence = 0.88

        likely_causes = [
            "Cilium or Calico Felix could not pass the BPF verifier against the node's kernel/BTF configuration",
            "RLIMIT_MEMLOCK is too low for the agent to pin required BPF maps and programs",
            "A BPF map reached its configured capacity and resize/replace failed under load",
            "TC or XDP hook attachment failed due to an existing qdisc, conflicting program, or renamed interface",
            "Kernel upgrade or missing BTF/debug info left the agent compiling programs incompatible with the running kernel",
            "Endpoint regeneration stalled while the agent process stayed alive, leaving stale dataplane state for existing Pods",
        ]

        suggested_checks = [
            f"kubectl describe pod {pod_name} -n {namespace}",
            f"kubectl get events -n {namespace} --field-selector involvedObject.name={pod_name}",
        ]

        if node_name:
            suggested_checks += [
                f"kubectl describe node {node_name}",
                "kubectl get pods -n kube-system -o wide | grep -E 'cilium|calico|antrea|aws-node'",
                f"kubectl logs -n kube-system -l k8s-app=cilium --field-selector spec.nodeName={node_name} --tail=200",
                f"kubectl logs -n calico-system -l k8s-app=calico-node --field-selector spec.nodeName={node_name} --tail=200",
                f"ssh {node_name} 'bpftool prog list 2>/dev/null | head -30'",
                f"ssh {node_name} 'bpftool map list 2>/dev/null | head -30'",
                f"ssh {node_name} 'dmesg | grep -i bpf | tail -20'",
                f"ssh {node_name} 'ulimit -l; sysctl kernel.unprivileged_bpf_disabled 2>/dev/null'",
            ]
        else:
            suggested_checks += [
                "Inspect cilium-agent / calico-node / antrea-agent logs for BPF verifier or attach failures",
                "On the affected node: bpftool prog list && bpftool map list",
                "On the affected node: dmesg | grep -i bpf",
            ]

        if is_verifier_rejection:
            suggested_checks.append(
                "Compare agent version with node kernel version and confirm BTF support is present"
            )
        if is_memlock:
            suggested_checks.append(
                "Raise memlock limits for the agent (container securityContext or systemd LimitMEMLOCK)"
            )
        if is_map_pressure:
            suggested_checks.append(
                "Review agent map-size settings and endpoint/service cardinality on the node"
            )
        if is_attach_failure:
            suggested_checks.append(
                "Inspect host interfaces and tc qdisc state: tc qdisc show dev <iface>"
            )

        return {
            "root_cause": (
                "eBPF dataplane program load or attach failed on the assigned node"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": likely_causes,
            "suggested_checks": suggested_checks,
        }
