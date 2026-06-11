from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeLocalDNSCacheUnavailableRule(FailureRule):
    """
    Detects workload DNS failures caused by an unavailable NodeLocal DNSCache
    agent on the Pod's assigned node.

    Real-world behavior:
    - clusters that run NodeLocal DNSCache usually configure Pods to query a
      node-local listener such as 169.254.20.10:53 or a local cache IP
    - CoreDNS can remain healthy while Pods on one node fail DNS because the
      node-local DNSCache DaemonSet pod is crashlooping, not Ready, probe-failing,
      or not scheduled on that node
    - kubelet and application events often show DNS timeouts, connection refused,
      "no such host", or resolver failures from Pods on the affected node
    - NodeLocal DNSCache itself may emit probe/backoff/configmap/mount/listener
      failures, or its DaemonSet may report unavailable desired pods

    Exclusions:
    - generic application DNS errors without NodeLocal DNSCache evidence
    - CoreDNS/kube-dns backend unavailability with no node-local cache failure
    - image pull, certificate, CNI sandbox, or NetworkPolicy failures
    """

    name = "NodeLocalDNSCacheUnavailable"
    category = "Networking"
    severity = "High"
    priority = 72
    deterministic = True

    phases = ["Pending", "Running"]
    container_states = ["waiting", "running", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "daemonset",
            "node",
            "configmap",
            "service",
            "endpoints",
            "endpointslice",
        ],
    }

    blocks = [
        "DNSResolutionFailure",
        "CoreDNSUnavailable",
    ]

    WINDOW_MINUTES = 20

    NODELOCAL_IDENTIFIERS = (
        "node-local-dns",
        "nodelocaldns",
        "node-local-dns-cache",
        "node-cache",
        "localdns",
        "local-dns",
        "k8s-app=node-local-dns",
        "k8s-app=nodelocaldns",
    )

    NODELOCAL_LISTENER_MARKERS = (
        "169.254.20.10",
        "169.254.25.10",
        "169.254.169.10",
        "node-local-dns",
        "nodelocaldns",
        "node local dns",
        "node-local dns",
        "local dns cache",
        "local dns",
    )

    DNS_FAILURE_MARKERS = (
        "dns lookup failed",
        "dns resolution",
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
        ":53",
        "read udp",
        "read tcp",
        "dial udp",
        "dial tcp",
        "i/o timeout",
        "io timeout",
        "connection refused",
        "connection reset by peer",
        "no route to host",
        "network is unreachable",
        "context deadline exceeded",
    )

    WORKLOAD_EXCLUSIONS = (
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "x509:",
        "certificate",
        "tls handshake",
        "failed to create pod sandbox",
        "failedcreatepodsandbox",
        "cni",
        "ipam",
        "networkpolicy",
        "network policy",
        "denied by",
        "conntrack",
    )

    NODELOCAL_FAILURE_REASONS = {
        "backoff",
        "failed",
        "unhealthy",
        "failedmount",
        "failedscheduling",
        "killing",
        "probeerror",
    }

    NODELOCAL_WAITING_REASONS = {
        "CrashLoopBackOff",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "ContainerCannotRun",
        "ErrImagePull",
        "ImagePullBackOff",
    }

    NODELOCAL_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "back-off restarting failed container",
        "crashloopbackoff",
        "failed to bind",
        "address already in use",
        "failed to listen",
        "bind: cannot assign requested address",
        "bind: address already in use",
        "failed to setup local dns",
        "failed to setup nodelocal dns",
        "failed to load config",
        "corefile",
        "configmap",
        "permission denied",
        "failedmount",
        "iptables",
        "ipvs",
        "cannot assign requested address",
        "connection refused",
        "loop detected",
        "panic",
    )

    NODELOCAL_RECOVERY_REASONS = {
        "Started",
        "Pulled",
        "Created",
        "Ready",
    }

    COREDNS_IDENTIFIERS = (
        "coredns",
        "kube-dns",
        "k8s-app=kube-dns",
        "k8s-app: kube-dns",
    )

    COREDNS_FAILURE_MARKERS = (
        "no endpoints available for service kube-dns",
        'no endpoints available for service "kube-dns"',
        "plugin/errors",
        "loop detected",
        "readiness probe failed",
        "liveness probe failed",
        "crashloopbackoff",
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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{key}={value}".lower() for key, value in labels.items())

    def _annotations_text(self, obj: dict[str, Any]) -> str:
        annotations = obj.get("metadata", {}).get("annotations", {}) or {}
        return " ".join(f"{key}={value}".lower() for key, value in annotations.items())

    def _identity_text(self, obj: dict[str, Any]) -> str:
        metadata = obj.get("metadata", {}) or {}
        spec = obj.get("spec", {}) or {}
        status = obj.get("status", {}) or {}
        names: list[str] = []
        for field in (
            spec.get("containers", []) or [],
            spec.get("initContainers", []) or [],
            status.get("containerStatuses", []) or [],
            status.get("initContainerStatuses", []) or [],
        ):
            for item in field:
                if isinstance(item, dict):
                    names.append(str(item.get("name") or ""))

        return " ".join(
            str(value).lower()
            for value in (
                metadata.get("name"),
                metadata.get("namespace"),
                metadata.get("generateName"),
                self._labels_text(obj),
                self._annotations_text(obj),
                *names,
            )
            if value
        )

    def _is_nodelocal_object(self, obj: dict[str, Any]) -> bool:
        namespace = self._object_namespace(obj)
        if namespace not in {"kube-system", "openshift-dns", "default"}:
            return False
        text = self._identity_text(obj)
        return any(marker in text for marker in self.NODELOCAL_IDENTIFIERS)

    def _is_coredns_object(self, obj: dict[str, Any]) -> bool:
        namespace = self._object_namespace(obj)
        if namespace != "kube-system":
            return False
        text = self._identity_text(obj)
        return any(marker in text for marker in self.COREDNS_IDENTIFIERS)

    def _targets_current_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind") or "").lower()
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
        if any(marker in message for marker in self.WORKLOAD_EXCLUSIONS):
            return False

        has_dns_semantics = any(
            marker in message for marker in self.DNS_FAILURE_MARKERS
        )
        has_dns_transport = any(
            marker in message for marker in self.DNS_TRANSPORT_MARKERS
        )
        references_nodelocal = any(
            marker in message for marker in self.NODELOCAL_LISTENER_MARKERS
        )

        if references_nodelocal and (has_dns_semantics or has_dns_transport):
            return True
        if has_dns_semantics and has_dns_transport:
            return True
        return has_dns_semantics and "dns" in message

    def _event_involves_nodelocal(self, event: dict[str, Any]) -> bool:
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

        text = " ".join(
            value
            for value in (
                involved_text,
                self._reason(event).lower(),
                self._message(event).lower(),
                self._source_component(event),
            )
            if value
        )
        return any(marker in text for marker in self.NODELOCAL_IDENTIFIERS)

    def _is_nodelocal_failure_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_nodelocal(event):
            return False
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        return reason in self.NODELOCAL_FAILURE_REASONS or any(
            marker in message for marker in self.NODELOCAL_FAILURE_MARKERS
        )

    def _event_targets_node(self, event: dict[str, Any], node_name: str | None) -> bool:
        if not node_name:
            return True
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if involved.get("nodeName") == node_name:
                return True
        message = self._message(event).lower()
        return node_name.lower() in message

    def _nodelocal_recovered_after(
        self,
        timeline: Timeline,
        failure_at: datetime | None,
        node_name: str | None,
    ) -> bool:
        for event in timeline.events:
            if self._reason(event) not in self.NODELOCAL_RECOVERY_REASONS:
                continue
            if not self._event_involves_nodelocal(event):
                continue
            if not self._event_targets_node(event, node_name):
                continue
            event_at = self._event_time(event)
            if failure_at is None or event_at is None or event_at >= failure_at:
                return True
        return False

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        if pod_obj.get("status", {}).get("phase") != "Running":
            return False
        conditions = pod_obj.get("status", {}).get("conditions", []) or []
        return any(
            condition.get("type") == "Ready" and condition.get("status") == "True"
            for condition in conditions
        )

    def _nodelocal_pods_for_node(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[dict[str, Any]]:
        pods = []
        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if not isinstance(pod_obj, dict) or not self._is_nodelocal_object(pod_obj):
                continue
            if node_name and pod_obj.get("spec", {}).get("nodeName") != node_name:
                continue
            pods.append(pod_obj)
        return pods

    def _degraded_nodelocal_pods(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[dict[str, Any]]:
        degraded = []
        for pod_obj in self._nodelocal_pods_for_node(context, node_name):
            status = pod_obj.get("status", {}) or {}
            if status.get("phase") not in {"Running", "Succeeded"}:
                degraded.append(pod_obj)
                continue

            if not self._pod_ready(pod_obj):
                degraded.append(pod_obj)
                continue

            for container in status.get("containerStatuses", []) or []:
                if not isinstance(container, dict):
                    continue
                state = container.get("state", {}) or {}
                waiting = state.get("waiting", {}) or {}
                terminated = state.get("terminated", {}) or {}
                last_terminated = (container.get("lastState", {}) or {}).get(
                    "terminated", {}
                ) or {}
                if waiting.get("reason") in self.NODELOCAL_WAITING_REASONS:
                    degraded.append(pod_obj)
                    break
                if terminated and int(terminated.get("exitCode", 0) or 0) != 0:
                    degraded.append(pod_obj)
                    break
                if (
                    last_terminated
                    and int(last_terminated.get("exitCode", 0) or 0) != 0
                    and int(container.get("restartCount", 0) or 0) > 0
                ):
                    degraded.append(pod_obj)
                    break
        return degraded

    def _nodelocal_daemonset_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        for daemonset in context.get("objects", {}).get("daemonset", {}).values():
            if not isinstance(daemonset, dict) or not self._is_nodelocal_object(
                daemonset
            ):
                continue
            status = daemonset.get("status", {}) or {}
            desired = int(status.get("desiredNumberScheduled", 0) or 0)
            available = int(status.get("numberAvailable", 0) or 0)
            unavailable = int(status.get("numberUnavailable", 0) or 0)
            ready = int(status.get("numberReady", 0) or 0)
            updated = int(status.get("updatedNumberScheduled", desired) or 0)

            if desired > 0 and (available < desired or ready < desired):
                return (
                    daemonset,
                    (
                        "NodeLocal DNSCache DaemonSet has "
                        f"desired={desired}, ready={ready}, available={available}, "
                        f"unavailable={unavailable}"
                    ),
                )
            if desired > 0 and updated < desired:
                return (
                    daemonset,
                    (
                        "NodeLocal DNSCache DaemonSet rollout is incomplete "
                        f"updated={updated}, desired={desired}"
                    ),
                )
        return None, None

    def _node_resolver_signal(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> str | None:
        if not node_name:
            return None
        node = context.get("objects", {}).get("node", {}).get(node_name)
        if not isinstance(node, dict):
            return None

        for condition in node.get("status", {}).get("conditions", []) or []:
            message = str(condition.get("message") or "")
            reason = str(condition.get("reason") or "")
            text = f"{reason} {message}".lower()
            if any(marker in text for marker in self.NODELOCAL_IDENTIFIERS) and any(
                marker in text for marker in self.NODELOCAL_FAILURE_MARKERS
            ):
                cond_type = condition.get("type", "Unknown")
                return (
                    f"Node condition {cond_type} references NodeLocal DNSCache "
                    f"failure: {message or reason}"
                )
        return None

    def _ready_coredns_pods(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        ready = []
        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if (
                isinstance(pod_obj, dict)
                and self._is_coredns_object(pod_obj)
                and self._pod_ready(pod_obj)
            ):
                ready.append(pod_obj)
        return ready

    def _kube_dns_has_ready_endpoints(self, context: dict[str, Any]) -> bool | None:
        endpoints_obj = next(
            (
                endpoint
                for endpoint in context.get("objects", {}).get("endpoints", {}).values()
                if isinstance(endpoint, dict)
                and endpoint.get("metadata", {}).get("name") == "kube-dns"
                and endpoint.get("metadata", {}).get("namespace", "kube-system")
                == "kube-system"
            ),
            None,
        )
        if isinstance(endpoints_obj, dict):
            for subset in endpoints_obj.get("subsets", []) or []:
                if subset.get("addresses"):
                    return True
            return False

        slices = context.get("objects", {}).get("endpointslice", {})
        relevant_slices = [
            slice_obj
            for slice_obj in slices.values()
            if isinstance(slice_obj, dict)
            and slice_obj.get("metadata", {}).get("namespace", "kube-system")
            == "kube-system"
            and (slice_obj.get("metadata", {}).get("labels", {}) or {}).get(
                "kubernetes.io/service-name"
            )
            == "kube-dns"
        ]
        if not relevant_slices:
            return None
        for slice_obj in relevant_slices:
            for endpoint in slice_obj.get("endpoints", []) or []:
                conditions = endpoint.get("conditions", {}) or {}
                if conditions.get("ready") is True and endpoint.get("addresses"):
                    return True
        return False

    def _clear_coredns_backend_failure(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> bool:
        endpoint_state = self._kube_dns_has_ready_endpoints(context)
        if endpoint_state is False:
            return True

        ready_coredns = self._ready_coredns_pods(context)
        coredns_pods = [
            pod_obj
            for pod_obj in context.get("objects", {}).get("pod", {}).values()
            if isinstance(pod_obj, dict) and self._is_coredns_object(pod_obj)
        ]
        if coredns_pods and not ready_coredns:
            return True

        for event in events:
            text = f"{self._reason(event)} {self._message(event)}".lower()
            involves_coredns = any(
                marker in text for marker in self.COREDNS_IDENTIFIERS
            )
            if involves_coredns and any(
                marker in text for marker in self.COREDNS_FAILURE_MARKERS
            ):
                return True
        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        node_name = pod.get("spec", {}).get("nodeName") or None
        recent_events = self._ordered_recent_events(timeline)
        dns_events = [
            event
            for event in recent_events
            if self._is_workload_dns_failure(event, pod)
        ]
        if not dns_events:
            return None

        nodelocal_events = [
            event
            for event in recent_events
            if self._is_nodelocal_failure_event(event)
            and self._event_targets_node(event, node_name)
        ]

        degraded_pods = self._degraded_nodelocal_pods(context, node_name)
        daemonset, daemonset_signal = self._nodelocal_daemonset_signal(context)
        node_signal = self._node_resolver_signal(context, node_name)

        if not nodelocal_events and not degraded_pods and not daemonset_signal:
            if not node_signal:
                return None

        # If the backend DNS layer is clearly down and the cache itself has no
        # independent failing pod/event, let CoreDNSUnavailable own the diagnosis.
        if (
            self._clear_coredns_backend_failure(recent_events, context)
            and not degraded_pods
            and not nodelocal_events
        ):
            return None

        latest_nodelocal_at = (
            self._event_time(nodelocal_events[-1]) if nodelocal_events else None
        )
        if nodelocal_events and self._nodelocal_recovered_after(
            timeline,
            latest_nodelocal_at,
            node_name,
        ):
            return None

        dns_occurrences = sum(self._occurrences(event) for event in dns_events)
        nodelocal_occurrences = sum(
            self._occurrences(event) for event in nodelocal_events
        )
        duration_seconds = timeline.duration_between(
            lambda event: self._is_workload_dns_failure(event, pod)
            or self._is_nodelocal_failure_event(event)
        )

        object_evidence: dict[str, list[str]] = {}
        degraded_signals: list[str] = []
        if degraded_pods:
            for pod_obj in degraded_pods[:3]:
                name = self._object_name(pod_obj)
                degraded_signals.append(
                    f"NodeLocal DNSCache pod {name} is not Ready or has a failing container"
                )
                object_evidence[f"pod:{name}"] = [
                    "NodeLocal DNSCache pod is degraded on the affected node"
                ]
        if daemonset_signal:
            daemonset_name = self._object_name(daemonset or {})
            degraded_signals.append(daemonset_signal)
            if daemonset_name:
                object_evidence[f"daemonset:{daemonset_name}"] = [daemonset_signal]
        if node_signal:
            degraded_signals.append(node_signal)
            if node_name:
                object_evidence[f"node:{node_name}"] = [node_signal]
        if nodelocal_events:
            degraded_signals.append(
                f"Recent NodeLocal DNSCache event: {self._message(nodelocal_events[-1])}"
            )
            object_evidence.setdefault("timeline:nodelocaldns", []).append(
                self._message(nodelocal_events[-1])
            )

        coredns_endpoint_state = self._kube_dns_has_ready_endpoints(context)
        if coredns_endpoint_state is True:
            degraded_signals.append(
                "kube-dns has ready backend endpoints, pointing to the node-local cache layer rather than CoreDNS itself"
            )
        elif self._ready_coredns_pods(context):
            degraded_signals.append(
                "CoreDNS has ready pod(s), while NodeLocal DNSCache has a separate failure signal"
            )

        return {
            "node_name": node_name,
            "dns_events": dns_events,
            "representative_dns_message": self._message(dns_events[-1]),
            "nodelocal_events": nodelocal_events,
            "representative_nodelocal_message": (
                self._message(nodelocal_events[-1]) if nodelocal_events else ""
            ),
            "dns_occurrences": dns_occurrences,
            "nodelocal_occurrences": nodelocal_occurrences,
            "degraded_signals": list(dict.fromkeys(degraded_signals)),
            "object_evidence": object_evidence,
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
            raise ValueError("NodeLocalDNSCacheUnavailable requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "NodeLocalDNSCacheUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = candidate["node_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_USES_NODELOCAL_DNSCACHE",
                    message="Pod DNS queries are routed through the node-local DNS cache listener before reaching kube-dns/CoreDNS",
                    role="runtime_context",
                ),
                Cause(
                    code="NODELOCAL_DNSCACHE_UNAVAILABLE",
                    message="NodeLocal DNSCache is unavailable or degraded on the affected node",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_DNS_QUERIES_FAIL_AT_NODE_CACHE",
                    message="Pod DNS lookups fail because the node-local cache cannot answer or forward DNS queries",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} has DNS failures in the recent incident window",
            f"Representative workload DNS failure: {candidate['representative_dns_message']}",
            (
                f"Observed {candidate['dns_occurrences']} workload DNS failure "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            ),
            "NodeLocal DNSCache degradation is evidenced separately from the workload DNS symptom",
        ]
        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")
        evidence.extend(candidate["degraded_signals"])
        if candidate["nodelocal_occurrences"]:
            evidence.append(
                f"Observed {candidate['nodelocal_occurrences']} NodeLocal DNSCache failure event occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            )
        if candidate["duration_seconds"]:
            evidence.append(
                f"DNS and NodeLocal DNSCache failure signals persisted for {candidate['duration_seconds'] / 60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [candidate["representative_dns_message"]],
            **candidate["object_evidence"],
        }
        if node_name:
            object_evidence.setdefault(f"node:{node_name}", []).append(
                "Workload DNS failures are tied to the node-local DNS cache path on this node"
            )

        confidence = 0.91
        if candidate["nodelocal_events"] and candidate["object_evidence"]:
            confidence = 0.98
        elif candidate["object_evidence"]:
            confidence = 0.96
        elif candidate["nodelocal_events"]:
            confidence = 0.94

        return {
            "rule": self.name,
            "root_cause": "NodeLocal DNSCache is unavailable on the pod's node",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "The node-local-dns DaemonSet pod on the affected node is not Ready or is crashlooping",
                "NodeLocal DNSCache could not bind its local listener address or program required node-local rules",
                "The NodeLocal DNSCache ConfigMap/Corefile is invalid or missing required upstream configuration",
                "A host networking, iptables/IPVS, or permission issue prevents the cache from serving DNS on the node",
                "The DaemonSet is unavailable or not scheduled on the affected node while Pods still use the node-local resolver IP",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                *(
                    [f"kubectl describe node {node_name}"]
                    if node_name
                    else [
                        "Identify the pod's assigned node and inspect node-local DNS state"
                    ]
                ),
                "kubectl get pods -n kube-system -l k8s-app=node-local-dns -o wide",
                "kubectl describe daemonset node-local-dns -n kube-system",
                "kubectl logs -n kube-system -l k8s-app=node-local-dns --tail=100",
                "kubectl get endpoints kube-dns -n kube-system",
                "Check the Pod resolver configuration for a node-local DNS IP such as 169.254.20.10",
            ],
        }
