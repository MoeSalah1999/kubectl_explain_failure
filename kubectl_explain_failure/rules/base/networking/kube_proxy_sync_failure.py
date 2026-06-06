from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class KubeProxySyncFailureRule(FailureRule):
    """
    Detects Service routing failures caused by kube-proxy failing to keep its
    iptables/ipvs/nftables rules synchronised with the current Service and
    Endpoint state — while the kube-proxy process itself remains alive.

    This rule is deliberately narrower than KubeProxyUnavailable.
    kube-proxy IS running (the DaemonSet Pod is Ready or at worst flapping
    through a sync error loop), but it is reporting repeated failures to apply,
    flush, or restore its rule set.  The net effect is that newly created
    Services or endpoint changes are not reflected in data-plane rules, so
    traffic to those Services silently drops or is routed to stale backends.

    Real-world behavior:
    - kube-proxy logs / events contain messages such as:
        "Failed to execute iptables-restore"
        "error syncing iptables rules"
        "Failed to sync iptables rules"
        "error syncing ipvs rules"
        "Failed to sync proxy rules"
        "syncProxyRules took longer than expected"
        "iptables: No chain/target/match by that name"
        "iptables: Resource temporarily unavailable"
        "error cleaning up stale rules"
        "failed to delete stale endpoint connections"
        "error listing endpoints"          ← API watch broken
        "failed to list *v1.Endpoints"     ← reflector error
        "failed to watch *v1.Service"
    - The failures are transient-looking (kube-proxy retries), which is why
      the process stays up, but they recur continuously: the sync loop never
      fully succeeds within its tick interval
    - Workload Pods that depend on Services created or updated after the last
      successful sync see connection failures to ClusterIPs or NodePorts
    - Node-level indicators: elevated iptables-restore stderr, lock contention
      (XTABLES_LOCKFD), ipset errors, or kernel module missing for ipvs

    Distinction from KubeProxyUnavailable:
    - KubeProxyUnavailable: proxy Pod is absent / crashlooping / NotReady
    - KubeProxySyncFailure:  proxy Pod is present and mostly alive, but its
      internal sync loop is producing repeated errors logged in events

    Scope:
    - Node data-plane layer (iptables/ipvs rule programming)
    - Deterministic when kube-proxy sync-failure events are observed together
      with workload connectivity symptoms on new or recently-changed Services
    - Fires even if the kube-proxy DaemonSet reports all Pods Ready, because
      the sync errors often do not yet propagate to the readiness probe

    Exclusions:
    - kube-proxy Pod is crashlooping or NotReady → KubeProxyUnavailable
    - CNI / IPAM failures (different layer)
    - CoreDNS outages (different layer)
    - NetworkPolicy explicit drops (deliberate, not a sync failure)
    - Connectivity failures to external (non-ClusterIP) destinations
    """

    name = "KubeProxySyncFailure"
    category = "Networking"
    severity = "High"
    priority = 71  # just below KubeProxyUnavailable (72)
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
        "KubeProxyUnavailable",
        "ServiceEndpointsEmpty",
        "DNSResolutionFailure",
        "EndpointSliceMissing",
        "ServicePortMismatch",
    ]

    WINDOW_MINUTES = 20

    # ------------------------------------------------------------------ #
    # kube-proxy identity                                                  #
    # ------------------------------------------------------------------ #

    KUBE_PROXY_IDENTIFIERS = (
        "kube-proxy",
        "kubeproxy",
        "kube_proxy",
    )

    # source.component values emitted by kube-proxy itself
    KUBE_PROXY_COMPONENTS = frozenset(
        {
            "kube-proxy",
            "kubeproxy",
        }
    )

    # ------------------------------------------------------------------ #
    # Sync-failure event markers                                           #
    # ------------------------------------------------------------------ #

    # Messages that confirm a sync-loop error rather than a crash
    SYNC_FAILURE_MARKERS = (
        # iptables proxier errors
        "failed to execute iptables-restore",
        "error syncing iptables rules",
        "failed to sync iptables rules",
        "iptables-restore failed",
        "iptables: resource temporarily unavailable",
        "iptables: no chain/target/match by that name",
        "xtables lock",
        "xtables_lockfd",
        "iptables lock",
        "error flushing chains",
        "error creating chain",
        "error cleaning up stale rules",
        # ipvs proxier errors
        "error syncing ipvs rules",
        "failed to sync ipvs rules",
        "failed to add ipvs service",
        "failed to delete ipvs service",
        "failed to update ipvs destinations",
        "ipvs proxier",
        "ipset error",
        "ipset:",
        # nftables proxier errors (k8s ≥ 1.29)
        "error syncing nftables rules",
        "failed to sync nftables rules",
        "nftables:",
        # generic proxier errors
        "failed to sync proxy rules",
        "syncproxyrules",
        "sync proxy rules",
        "error syncing proxy rules",
        "proxier sync",
        "proxy sync",
        "sync loop",
        "took longer than expected",
        "syncproxyrules took",
        # endpoint / service watch errors that prevent sync
        "error listing endpoints",
        "failed to list",
        "failed to watch",
        "reflector",
        "failed to delete stale endpoint connections",
        "error cleaning up stale endpoint connections",
        # stale / partial state
        "stale rules",
        "stale endpoints",
        "outdated endpoint",
        "out of sync",
        "rules are out of date",
    )

    # These indicate a complete crash rather than a sync loop — if they appear,
    # the event belongs to KubeProxyUnavailable instead
    CRASH_MARKERS = (
        "crashloopbackoff",
        "back-off restarting failed container",
        "oomkilled",
        "out of memory",
        "killed",
        "exit status",
        "container died",
        "liveness probe failed",  # indicates a hung/dead process
    )

    # Event reasons from kube-proxy that carry sync-failure semantics
    SYNC_FAILURE_REASONS = frozenset(
        {
            "syncrulesfailed",
            "proxyrulessyncrulesfailed",
            "syncfailed",
            "failed",
            "unhealthy",
        }
    )

    # ------------------------------------------------------------------ #
    # Workload connectivity markers (same scope as KubeProxyUnavailable)  #
    # ------------------------------------------------------------------ #

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
        "transport: error while dialing",
        "upstream connect error",
        "upstream request timeout",
        "503",
        "502",
    )

    # In-cluster destination indicators (ClusterIP / Service name)
    CLUSTER_SERVICE_MARKERS = (
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
        "cni",
        "ipam",
        "failedcreatepodsandbox",
        "failed to create pod sandbox",
    )

    # Recovery signals
    RECOVERY_MARKERS = (
        "successfully synced",
        "sync succeeded",
        "rules synced",
        "proxyrules synced",
        "syncproxyrules succeeded",
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

    def _labels_text(self, obj: dict[str, Any]) -> str:
        labels = obj.get("metadata", {}).get("labels", {}) or {}
        return " ".join(f"{k}={v}".lower() for k, v in labels.items())

    # ------------------------------------------------------------------ #
    # kube-proxy object recognition                                        #
    # ------------------------------------------------------------------ #

    def _is_kube_proxy_object(self, obj: dict[str, Any]) -> bool:
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
        return obj.get("spec", {}).get("nodeName") == node_name

    # ------------------------------------------------------------------ #
    # kube-proxy Pod liveness check                                        #
    # kube-proxy must be alive (not crashlooping/absent) for this rule.   #
    # If it is down, KubeProxyUnavailable is the correct diagnosis.       #
    # ------------------------------------------------------------------ #

    def _proxy_pod_is_alive(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> bool:
        """
        Return True when at least one kube-proxy Pod on the node exists and
        is not in a hard-crash state.  An absent proxy signals
        KubeProxyUnavailable, not a sync failure.
        """
        pods = context.get("objects", {}).get("pod", {}) or {}
        found_any = False

        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue
            if not self._is_kube_proxy_object(pod_obj):
                continue
            if node_name and not self._pod_on_node(pod_obj, node_name):
                continue

            found_any = True
            status = pod_obj.get("status", {}) or {}
            phase = status.get("phase", "")
            if phase in ("Failed", "Unknown"):
                continue

            # Check for crashloop / hard-crash waiting reason
            hard_crash = False
            for cs in status.get("containerStatuses", []) or []:
                waiting = (cs.get("state", {}) or {}).get("waiting", {}) or {}
                reason = waiting.get("reason", "")
                if reason in {"CrashLoopBackOff", "OOMKilled", "Error"}:
                    hard_crash = True
                    break
            if not hard_crash:
                return True  # at least one alive pod

        # No proxy Pod found at all → also signals KubeProxyUnavailable
        return not found_any  # treat absence as "alive" so we do NOT block here;
        # the absence check below will exclude us via the DaemonSet path.

    def _proxy_pod_exists_on_node(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> bool:
        pods = context.get("objects", {}).get("pod", {}) or {}
        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue
            if not self._is_kube_proxy_object(pod_obj):
                continue
            if node_name and not self._pod_on_node(pod_obj, node_name):
                continue
            return True
        return False

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

    def _is_sync_failure_event(self, event: dict[str, Any]) -> bool:
        """
        Return True when this event specifically describes a kube-proxy sync
        error — NOT a full crash (those belong to KubeProxyUnavailable).
        """
        if not self._event_involves_kube_proxy(event):
            return False

        message = self._message(event).lower()
        reason = self._reason(event).lower()

        # Exclude hard-crash events; let KubeProxyUnavailable own those
        if any(marker in message for marker in self.CRASH_MARKERS):
            return False

        # Accept by reason
        if reason in self.SYNC_FAILURE_REASONS:
            return any(marker in message for marker in self.SYNC_FAILURE_MARKERS)

        # Accept when the component is kube-proxy and message matches sync error
        component = self._source_component(event)
        if component in self.KUBE_PROXY_COMPONENTS:
            return any(marker in message for marker in self.SYNC_FAILURE_MARKERS)

        # Accept generic events that explicitly name kube-proxy and contain a
        # sync-failure marker (e.g. node events or kube-system events)
        return any(marker in message for marker in self.SYNC_FAILURE_MARKERS)

    def _is_proxy_sync_recovered(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_kube_proxy(event):
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.RECOVERY_MARKERS)

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
        if not self._targets_current_pod(event, pod):
            return False

        message = self._message(event)
        lowered = message.lower()

        if any(marker in lowered for marker in self.EXCLUDED_MARKERS):
            return False

        has_connectivity = any(
            marker in lowered for marker in self.WORKLOAD_CONNECTIVITY_MARKERS
        )
        if not has_connectivity:
            return False

        has_cluster_target = any(
            marker in lowered for marker in self.CLUSTER_SERVICE_MARKERS
        )
        return has_cluster_target

    # ------------------------------------------------------------------ #
    # Sync-specific node-object signals                                    #
    # ------------------------------------------------------------------ #

    def _node_iptables_signals(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> list[str]:
        """
        Inspect node conditions and annotations for iptables/ipvs state
        hints (e.g. NetworkUnavailable set by kube-proxy reporting sync loss).
        Returns human-readable signal strings.
        """
        signals: list[str] = []
        node_objs = context.get("objects", {}).get("node", {}) or {}

        for name, node in node_objs.items():
            if not isinstance(node, dict):
                continue
            if node_name and name != node_name:
                continue

            for condition in node.get("status", {}).get("conditions", []) or []:
                cond_type = str(condition.get("type", "") or "")
                cond_status = str(condition.get("status", "") or "").lower()
                cond_reason = str(condition.get("reason", "") or "").lower()
                cond_message = str(condition.get("message", "") or "").lower()

                # kube-proxy sets NetworkUnavailable=True when sync is broken
                if (
                    cond_type == "NetworkUnavailable"
                    and cond_status == "true"
                    and any(
                        kp in cond_reason or kp in cond_message
                        for kp in ("kube-proxy", "proxy", "iptables", "ipvs", "sync")
                    )
                ):
                    signals.append(
                        f"Node '{name}' condition NetworkUnavailable=True "
                        f"reason={condition.get('reason', '<unknown>')}"
                    )

        return signals

    # ------------------------------------------------------------------ #
    # Sustained-failure qualification                                      #
    # Sync errors are always retried, so we require the failures to be    #
    # sustained and recurring before firing, not just transient.          #
    # ------------------------------------------------------------------ #

    def _sync_failure_is_sustained(
        self,
        sync_events: list[dict[str, Any]],
        timeline: Timeline,
    ) -> bool:
        """
        Return True when sync failures are sustained enough to affect data-plane
        state. A single transient sync error is expected and recovered quickly;
        a prolonged or repeated sync failure causes stale rules.

        Requirements (mirrors the pattern in PreemptionIneffectiveDueToPDB):
        - total weighted occurrence count >= 2, OR
        - events span > 30 s (duration_between), OR
        - any single event has count >= 2 (kube-proxy has retried and failed)
        """
        if not sync_events:
            return False

        total_occurrences = sum(self._occurrences(e) for e in sync_events)
        if total_occurrences >= 2:
            return True

        # Check duration
        duration = timeline.duration_between(self._is_sync_failure_event)
        if duration >= 30:
            return True

        # Any event with count >= 2 means kube-proxy logged it more than once
        if any(self._occurrences(e) >= 2 for e in sync_events):
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

        # 1. Identify sync-failure events from kube-proxy
        sync_events = [
            event for event in recent_events if self._is_sync_failure_event(event)
        ]
        if not sync_events:
            return None

        # 2. Failures must be sustained, not a single transient blip
        if not self._sync_failure_is_sustained(sync_events, timeline):
            return None

        # 3. Guard: if a recovery was observed after the last sync failure, skip
        latest_sync_failure_at = self._event_time(sync_events[-1])
        for event in timeline.events:
            if not self._is_proxy_sync_recovered(event):
                continue
            recovered_at = self._event_time(event)
            if (
                latest_sync_failure_at is None
                or recovered_at is None
                or recovered_at >= latest_sync_failure_at
            ):
                return None  # proxy has recovered

        node_name = self._node_for_pod(pod)

        # 4. Guard: if the proxy Pod is hard-crashing, defer to KubeProxyUnavailable
        #    We check whether ALL proxy pods are in crash state — if so, hand off.
        pods_obj = context.get("objects", {}).get("pod", {}) or {}
        has_any_proxy_pod = any(
            isinstance(p, dict)
            and self._is_kube_proxy_object(p)
            and (not node_name or self._pod_on_node(p, node_name))
            for p in pods_obj.values()
        )
        if has_any_proxy_pod:
            all_crashing = all(
                (
                    (p.get("status", {}) or {}).get("phase", "")
                    in ("Failed", "Unknown")
                    or any(
                        ((cs.get("state", {}) or {}).get("waiting", {}) or {}).get(
                            "reason", ""
                        )
                        in {"CrashLoopBackOff", "OOMKilled", "Error"}
                        for cs in (p.get("status", {}) or {}).get(
                            "containerStatuses", []
                        )
                        or []
                    )
                )
                for p in pods_obj.values()
                if isinstance(p, dict)
                and self._is_kube_proxy_object(p)
                and (not node_name or self._pod_on_node(p, node_name))
            )
            if all_crashing:
                # Full crash — KubeProxyUnavailable is the right rule
                return None

        # 5. Workload connectivity failure (corroborating symptom, not required
        #    when sync-failure events are explicit and sustained from kube-proxy)
        workload_events = [
            event
            for event in recent_events
            if self._is_workload_connectivity_failure(event, pod)
        ]

        # 6. Node-level iptables/NetworkUnavailable signals
        node_signals = self._node_iptables_signals(context, node_name)

        sync_occurrences = sum(self._occurrences(e) for e in sync_events)
        workload_occurrences = sum(self._occurrences(e) for e in workload_events)
        duration_seconds = timeline.duration_between(self._is_sync_failure_event)

        # Extract the dominant sync-failure message for the explanation
        all_msgs = [self._message(e) for e in sync_events if self._message(e)]
        dominant_sync_msg = max(set(all_msgs), key=all_msgs.count) if all_msgs else ""

        # Identify the proxier backend in use (iptables / ipvs / nftables)
        proxier_backend = "iptables"
        combined_text = " ".join(all_msgs).lower()
        if "ipvs" in combined_text:
            proxier_backend = "ipvs"
        elif "nftables" in combined_text:
            proxier_backend = "nftables"

        return {
            "node_name": node_name,
            "sync_events": sync_events,
            "workload_events": workload_events,
            "node_signals": node_signals,
            "sync_occurrences": sync_occurrences,
            "workload_occurrences": workload_occurrences,
            "duration_seconds": duration_seconds,
            "dominant_sync_msg": dominant_sync_msg,
            "proxier_backend": proxier_backend,
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
            raise ValueError("KubeProxySyncFailure requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("KubeProxySyncFailure explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = candidate["node_name"]
        # sync_events = candidate["sync_events"]
        workload_events = candidate["workload_events"]
        node_signals = candidate["node_signals"]
        sync_occurrences = candidate["sync_occurrences"]
        workload_occurrences = candidate["workload_occurrences"]
        duration_seconds = candidate["duration_seconds"]
        dominant_sync_msg = candidate["dominant_sync_msg"]
        proxier_backend = candidate["proxier_backend"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="KUBE_PROXY_SYNC_LOOP_FAILING",
                    message=(
                        f"kube-proxy {proxier_backend} sync loop is reporting "
                        "repeated errors and cannot keep data-plane rules current"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SERVICE_ROUTING_RULES_STALE",
                    message=(
                        f"Node {proxier_backend} rules for new or changed Services "
                        "are absent or stale because the sync has not completed"
                    ),
                    role="infrastructure_intermediate",
                ),
                Cause(
                    code="WORKLOAD_CONNECTIVITY_DEGRADED",
                    message=(
                        "Traffic to ClusterIP Services updated after the last "
                        "successful sync is dropped or routed to stale backends"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence: list[str] = [
            (
                f"kube-proxy {proxier_backend} sync loop produced "
                f"{sync_occurrences} error occurrence(s) within "
                f"the last {self.WINDOW_MINUTES} minutes"
            ),
        ]
        if dominant_sync_msg:
            evidence.append(f"Representative sync-failure message: {dominant_sync_msg}")
        if duration_seconds >= 30:
            evidence.append(
                f"kube-proxy sync failures persisted for "
                f"{duration_seconds / 60:.1f} minutes without recovery"
            )
        evidence.extend(node_signals)
        if workload_events:
            representative_workload = self._message(workload_events[-1])
            evidence.append(
                f"Workload connectivity failure observed "
                f"{workload_occurrences} time(s): {representative_workload}"
            )
        if node_name:
            evidence.append(f"Affected node: {node_name}")

        object_evidence: dict[str, list[str]] = {}
        if node_name:
            node_ev: list[str] = [
                f"kube-proxy {proxier_backend} sync is failing on this node"
            ]
            if dominant_sync_msg:
                node_ev.append(dominant_sync_msg)
            node_ev.extend(node_signals)
            object_evidence[f"node:{node_name}"] = node_ev

        if workload_events:
            object_evidence[f"pod:{pod_name}"] = [self._message(workload_events[-1])]

        object_evidence["daemonset:kube-proxy"] = [
            f"kube-proxy {proxier_backend} sync loop is producing errors; "
            "Pod may appear Ready but data-plane rules are not up to date"
        ]

        # Confidence: sync events from kube-proxy are authoritative when
        # sustained; workload symptoms add corroboration.
        confidence = 0.88
        if workload_events and node_signals:
            confidence = 0.97
        elif workload_events and duration_seconds >= 60:
            confidence = 0.95
        elif workload_events:
            confidence = 0.92
        elif node_signals:
            confidence = 0.91
        elif duration_seconds >= 60:
            confidence = 0.90

        node_log_cmd = (
            f"kubectl logs -n kube-system -l k8s-app=kube-proxy "
            f"--field-selector spec.nodeName={node_name} --tail=200"
            if node_name
            else "kubectl logs -n kube-system -l k8s-app=kube-proxy --tail=200"
        )

        return {
            "root_cause": (
                f"kube-proxy {proxier_backend} sync is failing: "
                "Service routing rules on the node are stale or incomplete"
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
                f"Kernel {proxier_backend}/iptables modules are missing or "
                "the kube-proxy process lacks the required capabilities",
                "iptables or ipset lock contention (XTABLES_LOCKFD) is blocking "
                "kube-proxy from acquiring the lock within its sync interval",
                "kube-proxy cannot reach the Kubernetes API server to fetch "
                "Service or Endpoint updates, causing its reflector to fall behind",
                "A recent kernel upgrade removed or renamed an iptables chain "
                "or ipvs module that kube-proxy depends on",
                "Excessive Service/Endpoint churn is overwhelming kube-proxy's "
                "sync interval, causing rules to be perpetually out of date",
                "A concurrent tool (firewalld, another iptables manager) is "
                "flushing or modifying the chains that kube-proxy owns",
            ],
            "suggested_checks": [
                "kubectl get events -n kube-system | grep -i 'proxy\\|sync\\|iptables\\|ipvs'",
                node_log_cmd,
                "kubectl describe daemonset kube-proxy -n kube-system",
                "kubectl get pods -n kube-system -l k8s-app=kube-proxy -o wide",
                *(
                    [
                        f"kubectl describe node {node_name}",
                        f"ssh {node_name} -- iptables -L KUBE-SERVICES | head -20",
                        f"ssh {node_name} -- iptables-save | grep -c KUBE",
                    ]
                    if node_name
                    else ["kubectl get nodes -o wide"]
                ),
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
