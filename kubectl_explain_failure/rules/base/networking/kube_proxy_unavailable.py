from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class KubeProxyUnavailableRule(FailureRule):
    """
    Detects workload connectivity failures whose root cause is a degraded or
    absent kube-proxy on the Pod's assigned node.

    Real-world behavior:
    - kube-proxy is responsible for programming iptables/ipvs/nftables rules
      that implement Service ClusterIP and NodePort routing on every node
    - when kube-proxy is absent, crashlooping, or unable to sync rules, traffic
      sent to a ClusterIP silently drops or is refused because the DNAT rules
      that would route it to a backend Pod do not exist
    - the workload Pod itself may be Running and healthy, but any outbound call
      to a ClusterIP (including the Kubernetes API Service at 10.96.0.1:443 or
      equivalent) fails with "connection refused", "i/o timeout", or
      "no route to host"
    - common signals:
        * kube-proxy DaemonSet has unavailable replicas on the affected node
        * kube-proxy Pod on the node is crashlooping, NotReady, or absent
        * kube-proxy events mention "failed to sync", "iptables", "ipvs",
          "proxier", "syncProxyRules", or "failed to update endpoints"
        * the workload pod emits repeated connection-failure events targeting
          ClusterIP addresses or well-known in-cluster hostnames such as
          "kubernetes.default", "kubernetes.default.svc", or any .svc.cluster.local
        * node-level kube-proxy health-check endpoint stops responding

    Exclusions:
    - CNI or IPAM failures (different layer; handled by CNI rules)
    - CoreDNS outages (covered by CoreDNSUnavailable)
    - NetworkPolicy denials (packets dropped deliberately, not proxy absence)
    - iptables rule conflicts unrelated to kube-proxy (e.g. external firewall)
    - kube-proxy Pod scheduling failures (covered by scheduling rules)
    - cluster-external connectivity failures where the destination is not a
      ClusterIP/Service name
    """

    name = "KubeProxyUnavailable"
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
        ],
    }

    blocks = [
        "ServiceEndpointsEmpty",
        "DNSResolutionFailure",
        "EndpointSliceMissing",
        "ServicePortMismatch",
    ]

    WINDOW_MINUTES = 20

    # Identifiers used to recognise kube-proxy objects / events
    KUBE_PROXY_IDENTIFIERS = (
        "kube-proxy",
        "kubeproxy",
        "kube_proxy",
    )

    # kube-proxy component names as reported in event source.component
    KUBE_PROXY_COMPONENTS = frozenset(
        {
            "kube-proxy",
            "kubeproxy",
        }
    )

    # Event reasons that indicate a kube-proxy Pod is unhealthy
    KUBE_PROXY_FAILURE_REASONS = frozenset(
        {
            "backoff",
            "unhealthy",
            "failed",
            "killing",
            "failedscheduling",
            "oomkilled",
        }
    )

    # Message fragments in kube-proxy events that confirm proxy-rule failure
    KUBE_PROXY_FAILURE_MARKERS = (
        "failed to sync",
        "failed to update",
        "failed to delete",
        "failed to apply",
        "syncproxyrules",
        "sync proxy rules",
        "proxier error",
        "iptables",
        "ipvs",
        "nftables",
        "failed to create or update endpoints",
        "failed to create endpoints",
        "endpoints update failed",
        "readiness probe failed",
        "liveness probe failed",
        "crashloopbackoff",
        "back-off restarting failed container",
        "oom",
        "out of memory",
        "failed to bind",
        "healthcheck failed",
        "healthz failed",
        "failed to run proxier",
        "proxier failed",
        "cannot sync",
        "unable to sync",
        "timed out waiting",
    )

    # Workload-side connectivity failure markers that indicate Service routing
    # is broken (these are the symptoms on the affected workload Pod)
    WORKLOAD_CONNECTIVITY_MARKERS = (
        "connection refused",
        "connect: connection refused",
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "no route to host",
        "connection reset by peer",
        "connection timed out",
        "network is unreachable",
        "eof",
        "connection closed before server preauth",
        "transport: error while dialing",
        "upstream connect error",
        "upstream request timeout",
        "503",
        "502",
    )

    # In-cluster hostname fragments that indicate a ClusterIP/Service target
    # rather than an external host
    CLUSTER_SERVICE_MARKERS = (
        "kubernetes.default",
        "svc.cluster.local",
        ".svc.",
        "cluster.local",
        "10.96.",  # common default service CIDR prefix
        "10.0.0.",  # common alternative service CIDR prefix
        "172.20.",  # common EKS service CIDR prefix
        "172.16.",  # common service CIDR prefix
        "192.168.0.",  # less common but valid service CIDR
    )

    # Messages / reasons that indicate the workload failure is NOT due to
    # kube-proxy (to avoid false positives)
    EXCLUDED_MARKERS = (
        "no such host",
        "dns lookup",
        "cannot resolve",
        "failed to resolve",
        "lookup ",
        "x509:",
        "certificate",
        "tls handshake",
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "oom killed",
        "cni",
        "ipam",
        "failed to create pod sandbox",
        "failedcreatepodsandbox",
    )

    # Recovery signals that indicate kube-proxy has come back
    RECOVERY_REASONS = frozenset(
        {
            "Started",
            "Pulled",
            "Created",
            "Ready",
        }
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

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{k}={v}".lower() for k, v in labels.items())

    # ------------------------------------------------------------------ #
    # kube-proxy object recognition                                        #
    # ------------------------------------------------------------------ #

    def _is_kube_proxy_object(self, obj: dict[str, Any]) -> bool:
        """Return True when the object is identifiable as kube-proxy."""
        text = " ".join(
            v.lower()
            for v in (
                self._object_name(obj),
                self._labels_text(obj),
                str(obj.get("metadata", {}).get("generateName") or ""),
            )
            if v
        )
        return any(identifier in text for identifier in self.KUBE_PROXY_IDENTIFIERS)

    def _node_for_pod(self, pod: dict[str, Any]) -> str | None:
        return pod.get("spec", {}).get("nodeName") or None

    def _pod_on_node(self, obj: dict[str, Any], node_name: str) -> bool:
        """Return True if a Pod object is scheduled to *node_name*."""
        return obj.get("spec", {}).get("nodeName") == node_name

    # ------------------------------------------------------------------ #
    # kube-proxy DaemonSet degradation                                    #
    # ------------------------------------------------------------------ #

    def _daemonset_degraded_on_node(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[str]:
        """
        Inspect kube-proxy DaemonSet status for evidence of degradation.

        Returns a list of human-readable signal strings (empty = no signal).
        """
        signals: list[str] = []
        daemonsets = context.get("objects", {}).get("daemonset", {}) or {}

        for ds in daemonsets.values():
            if not isinstance(ds, dict) or not self._is_kube_proxy_object(ds):
                continue

            ds_name = self._object_name(ds)
            status = ds.get("status", {}) or {}
            desired = status.get("desiredNumberScheduled", 0)
            available = status.get("numberAvailable", 0)
            ready = status.get("numberReady", 0)
            unavailable = status.get("numberUnavailable", 0)
            misscheduled = status.get("numberMisscheduled", 0)

            if unavailable and unavailable > 0:
                signals.append(
                    f"kube-proxy DaemonSet '{ds_name}' has "
                    f"{unavailable} unavailable node(s) "
                    f"(desired={desired}, available={available})"
                )
            elif desired > 0 and ready < desired:
                signals.append(
                    f"kube-proxy DaemonSet '{ds_name}' has only "
                    f"{ready}/{desired} ready Pods"
                )
            if misscheduled > 0:
                signals.append(
                    f"kube-proxy DaemonSet '{ds_name}' has "
                    f"{misscheduled} misscheduled Pod(s)"
                )

        return signals

    # ------------------------------------------------------------------ #
    # kube-proxy Pod degradation                                          #
    # ------------------------------------------------------------------ #

    def _kube_proxy_pod_signals(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[str]:
        """
        Inspect kube-proxy Pod objects for degradation evidence on the
        relevant node (or cluster-wide if node is unknown).
        """
        signals: list[str] = []
        pods = context.get("objects", {}).get("pod", {}) or {}

        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue
            if not self._is_kube_proxy_object(pod_obj):
                continue
            if node_name and not self._pod_on_node(pod_obj, node_name):
                continue

            proxy_pod_name = self._object_name(pod_obj)
            status = pod_obj.get("status", {}) or {}
            phase = status.get("phase", "")

            if phase in ("Failed", "Unknown"):
                signals.append(f"kube-proxy Pod '{proxy_pod_name}' is in phase {phase}")
                continue

            # Check Ready condition
            ready = any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in status.get("conditions", []) or []
            )
            if not ready:
                signals.append(f"kube-proxy Pod '{proxy_pod_name}' is not Ready")

            # Check container waiting reasons
            for cs in status.get("containerStatuses", []) or []:
                waiting = (cs.get("state", {}) or {}).get("waiting", {}) or {}
                reason = waiting.get("reason", "")
                if reason in {
                    "CrashLoopBackOff",
                    "OOMKilled",
                    "Error",
                    "RunContainerError",
                    "CreateContainerConfigError",
                }:
                    signals.append(
                        f"kube-proxy Pod '{proxy_pod_name}' container "
                        f"waiting reason={reason}"
                    )

            # Check restart count
            for cs in status.get("containerStatuses", []) or []:
                restarts = cs.get("restartCount", 0)
                if isinstance(restarts, int) and restarts >= 3:
                    signals.append(
                        f"kube-proxy Pod '{proxy_pod_name}' has restarted "
                        f"{restarts} time(s)"
                    )

        return signals

    # ------------------------------------------------------------------ #
    # Event classification                                                 #
    # ------------------------------------------------------------------ #

    def _event_involves_kube_proxy(self, event: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        involved_text = ""
        if isinstance(involved, dict):
            involved_text = " ".join(
                str(v).lower()
                for v in (
                    involved.get("namespace"),
                    involved.get("name"),
                    involved.get("kind"),
                    involved.get("fieldPath"),
                )
                if v
            )
        component = self._source_component(event)
        text = f"{involved_text} {self._message(event).lower()} {component}"
        return any(identifier in text for identifier in self.KUBE_PROXY_IDENTIFIERS)

    def _is_kube_proxy_failure_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_kube_proxy(event):
            return False
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        return reason in self.KUBE_PROXY_FAILURE_REASONS or any(
            marker in message for marker in self.KUBE_PROXY_FAILURE_MARKERS
        )

    def _is_kube_proxy_recovery_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_kube_proxy(event):
            return False
        return self._reason(event) in self.RECOVERY_REASONS

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

    def _is_workload_connectivity_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        """
        Return True when this event represents a workload-side connectivity
        symptom that is consistent with broken Service routing (kube-proxy
        absence) rather than a DNS, CNI, or certificate problem.
        """
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

        # Require at least one in-cluster service target indicator, OR no
        # external hostname pattern (i.e. the destination looks internal)
        has_cluster_target = any(
            marker in lowered for marker in self.CLUSTER_SERVICE_MARKERS
        )
        # Heuristic: if the message contains a plain IP that looks like a
        # service CIDR address we accept it even without a hostname marker
        return has_cluster_target

    # ------------------------------------------------------------------ #
    # Recovery guard                                                       #
    # ------------------------------------------------------------------ #

    def _proxy_recovered_after(
        self,
        timeline: Timeline,
        latest_failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_kube_proxy_recovery_event(event):
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

        # 1. Workload must show in-cluster connectivity symptoms
        workload_events = [
            event
            for event in recent_events
            if self._is_workload_connectivity_failure(event, pod)
        ]
        if not workload_events:
            return None

        node_name = self._node_for_pod(pod)

        # 2. Gather kube-proxy degradation signals
        proxy_events = [
            event for event in recent_events if self._is_kube_proxy_failure_event(event)
        ]
        ds_signals = self._daemonset_degraded_on_node(context, node_name)
        pod_signals = self._kube_proxy_pod_signals(context, node_name)

        object_signals = ds_signals + pod_signals

        # At least one corroborating signal from kube-proxy itself is required
        if not proxy_events and not object_signals:
            return None

        # 3. Guard: if kube-proxy recovered after the last failure, don't fire
        latest_proxy_failure_at = (
            self._event_time(proxy_events[-1]) if proxy_events else None
        )
        if proxy_events and self._proxy_recovered_after(
            timeline, latest_proxy_failure_at
        ):
            return None

        workload_occurrences = sum(
            self._occurrences(event) for event in workload_events
        )
        proxy_occurrences = sum(self._occurrences(event) for event in proxy_events)
        duration_seconds = timeline.duration_between(
            lambda event: self._is_workload_connectivity_failure(event, pod)
            or self._is_kube_proxy_failure_event(event)
        )

        return {
            "node_name": node_name,
            "workload_events": workload_events,
            "proxy_events": proxy_events,
            "object_signals": object_signals,
            "ds_signals": ds_signals,
            "pod_signals": pod_signals,
            "workload_occurrences": workload_occurrences,
            "proxy_occurrences": proxy_occurrences,
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
            raise ValueError("KubeProxyUnavailable requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("KubeProxyUnavailable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = candidate["node_name"]
        workload_events = candidate["workload_events"]
        proxy_events = candidate["proxy_events"]
        object_signals = candidate["object_signals"]
        workload_occurrences = candidate["workload_occurrences"]
        proxy_occurrences = candidate["proxy_occurrences"]
        duration_seconds = candidate["duration_seconds"]

        representative_workload = self._message(workload_events[-1])
        representative_proxy = self._message(proxy_events[-1]) if proxy_events else ""

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_DEPENDS_ON_SERVICE_ROUTING",
                    message="Pod relies on kube-proxy iptables/ipvs rules to reach ClusterIP Services",
                    role="runtime_context",
                ),
                Cause(
                    code="KUBE_PROXY_UNAVAILABLE",
                    message=(
                        "kube-proxy is degraded or absent on the node and cannot "
                        "program Service routing rules"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SERVICE_ROUTING_RULES_ABSENT",
                    message=(
                        "Without kube-proxy rules, ClusterIP traffic is dropped "
                        "or refused, causing workload connectivity failures"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence: list[str] = [
            f"Pod {namespace}/{pod_name} has in-cluster Service connectivity failures",
            f"Representative workload failure: {representative_workload}",
            (
                f"Observed {workload_occurrences} in-cluster connectivity failure "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            ),
            "kube-proxy degradation is evidenced separately from the workload symptom",
        ]
        evidence.extend(object_signals)
        if representative_proxy:
            evidence.append(
                f"Representative kube-proxy failure event: {representative_proxy}"
            )
        if proxy_occurrences:
            evidence.append(
                f"Observed {proxy_occurrences} kube-proxy failure event occurrence(s) "
                f"within the last {self.WINDOW_MINUTES} minutes"
            )
        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")
        if duration_seconds:
            evidence.append(
                f"kube-proxy and workload failure signals persisted for "
                f"{duration_seconds / 60:.1f} minutes"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [representative_workload],
        }
        if node_name:
            node_signals: list[str] = ["kube-proxy is degraded or absent on this node"]
            if representative_proxy:
                node_signals.append(representative_proxy)
            object_evidence[f"node:{node_name}"] = node_signals
        if candidate["ds_signals"]:
            object_evidence["daemonset:kube-proxy"] = list(candidate["ds_signals"])
        if candidate["pod_signals"]:
            object_evidence.setdefault("pod:kube-proxy", []).extend(
                candidate["pod_signals"]
            )

        # Confidence: highest when we have both workload symptoms and
        # independent kube-proxy object-graph evidence; lower when only events.
        confidence = 0.88
        if object_signals and proxy_events:
            confidence = 0.97
        elif object_signals:
            confidence = 0.94
        elif proxy_events:
            confidence = 0.91

        return {
            "root_cause": (
                "kube-proxy is unavailable and Service routing rules are not programmed on the node"
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
                "kube-proxy DaemonSet Pod is crashlooping, OOMKilled, or stuck in a restart loop",
                "kube-proxy failed to sync iptables/ipvs rules due to a kernel module or permission issue",
                "kube-proxy was evicted, drained, or deleted from the node without a replacement being scheduled",
                "A kernel upgrade or node reboot flushed iptables/ipvs state and kube-proxy did not recover",
                "kube-proxy is running but cannot reach the API server to fetch Service/Endpoint updates",
            ],
            "suggested_checks": [
                "kubectl get pods -n kube-system -l k8s-app=kube-proxy -o wide",
                "kubectl describe daemonset kube-proxy -n kube-system",
                *(
                    [
                        f"kubectl logs -n kube-system -l k8s-app=kube-proxy --field-selector spec.nodeName={node_name} --tail=100"
                    ]
                    if node_name
                    else [
                        "kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=100"
                    ]
                ),
                "kubectl get events -n kube-system | grep -i kube-proxy",
                f"kubectl describe pod {pod_name} -n {namespace}",
                *([f"kubectl describe node {node_name}"] if node_name else []),
            ],
        }
