from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class IPTablesRestoreFailureRule(FailureRule):
    """
    Detects pod networking failures caused by iptables-restore or
    ip6tables-restore errors on the assigned node.

    Real-world interpretation:
    - Kubernetes network plugins (kube-proxy, Calico, Cilium in iptables mode,
      Flannel, Canal) apply forwarding and masquerade rules by piping a ruleset
      through iptables-restore / ip6tables-restore.
    - If the kernel rejects the ruleset — because another process holds the
      xtables lock, the kernel module is missing, or a rule contains a syntax
      error — the network plugin logs a failure and is unable to program the
      data plane.
    - Pods on that node may be assigned and reach the kubelet, but sandbox
      creation or connectivity setup fails because the required FORWARD /
      POSTROUTING / NAT rules are absent or inconsistent.
    - kube-proxy will also emit these events when it cannot apply its full
      ruleset, causing cluster-wide service routing to be broken for pods on
      the affected node.

    Signal sources:
    - Kubernetes events with reason NetworkNotReady, FailedCreatePodSandbox,
      or CNIPluginFailure where the message mentions iptables-restore,
      ip6tables-restore, or the xtables lock.
    - Events emitted by kube-proxy pods on the same node (reason=Unhealthy /
      Failed with iptables-restore in the message).
    - Node conditions: NetworkUnavailable=True.

    Exclusions:
    - Pure kube-proxy crash loops unrelated to iptables (e.g. API server
      auth errors, image pull failures) — the message must reference iptables.
    - IP exhaustion / IPAM failures.
    - Container-runtime socket errors (containerd / CRI-O unavailable).
    - Missing CNI config-file errors that are unrelated to rules programming.
    - Transient one-off occurrences below the recurrence threshold when no
      corroborating node condition is present.
    """

    name = "IPTablesRestoreFailure"
    category = "Networking"
    severity = "High"
    priority = 70
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline", "node", "node_conditions"],
    }

    blocks = [
        "CNIPluginFailure",
        "NetworkUnavailable",
    ]

    # ------------------------------------------------------------------ #
    # Tuning knobs                                                         #
    # ------------------------------------------------------------------ #

    WINDOW_MINUTES = 30

    # Minimum cumulative occurrences (sum of event.count) needed to fire
    # when no corroborating NetworkUnavailable node condition is present.
    MIN_OCCURRENCES_WITHOUT_NODE_CONDITION = 2

    # ------------------------------------------------------------------ #
    # Event reason classifiers                                             #
    # ------------------------------------------------------------------ #

    # Reasons that may carry an iptables-restore failure message emitted by
    # the network plugin or kube-proxy on behalf of a workload pod.
    SANDBOX_REASONS = {
        "failedcreatepodsandbox",
        "cnipluginfailure",
        "networknotready",
        "failed",
        "unhealthy",
        "backoff",
    }

    # Reasons emitted by kube-proxy that indicate node-wide iptables issues.
    KUBE_PROXY_REASONS = {
        "unhealthy",
        "failed",
        "backoff",
    }

    SUCCESS_REASONS = {
        "Started",
        "Created",
        "AddedInterface",
        "SandboxChanged",
    }

    # ------------------------------------------------------------------ #
    # Message markers                                                      #
    # ------------------------------------------------------------------ #

    # At least one of these must appear in the event message.
    IPTABLES_MARKERS = (
        "iptables-restore",
        "ip6tables-restore",
        "iptables restore",
        "ip6tables restore",
        "xtables lock",
        "xtables-lock",
        "iptables: ",
        "ip6tables: ",
        "failed to run 'iptables-restore'",
        "failed to run 'ip6tables-restore'",
        "error running iptables",
        "error running ip6tables",
        "could not restore iptables",
        "could not restore ip6tables",
        "iptables-legacy",
        "iptables-nft",
        "unable to ensure iptables",
        "unable to set up iptables",
        "could not apply iptables rules",
        "applying iptables rules failed",
        "kube-proxy: could not load iptables",
    )

    # Markers that indicate a *different* root cause and should suppress
    # this rule to avoid false positives.
    EXCLUDED_MARKERS = (
        # Container-runtime unavailability
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "runtime.v1.runtimeservice",
        "containerd.sock",
        "cri-o.sock",
        "connection refused",
        # IPAM / IP pool exhaustion
        "no available ip",
        "no more ips",
        "ipam exhausted",
        "address pool exhausted",
        "failed to allocate ip",
        "failed to assign an ip",
        # Missing CNI config — separate rule handles this
        "cni config uninitialized",
        "no networks found in /etc/cni/net.d",
        "no valid networks found in /etc/cni/net.d",
        "failed to load cni config",
        "network plugin is not ready",
        # API server auth issues common in kube-proxy restarts
        "unauthorized",
        "forbidden",
        "certificateexpired",
        "x509",
        # Image pull problems
        "imagepullbackoff",
        "errimagepull",
        "image pull",
    )

    # kube-proxy component name patterns used to scope proxy-sourced events.
    KUBE_PROXY_COMPONENT_MARKERS = (
        "kube-proxy",
        "kubeproxy",
    )

    # Pod name prefixes that identify kube-proxy DaemonSet pods.
    KUBE_PROXY_POD_MARKERS = (
        "kube-proxy",
        "kubeproxy",
    )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        """Prefer eventTime, fall back through lastTimestamp → firstTimestamp."""
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "").lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _involved_kind(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("kind") or "").lower()

    def _involved_name(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("name") or "")

    def _involved_namespace(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("namespace") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

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

    # ------------------------------------------------------------------ #
    # Event classification                                                 #
    # ------------------------------------------------------------------ #

    def _has_iptables_marker(self, message: str) -> bool:
        lc = message.lower()
        return any(marker in lc for marker in self.IPTABLES_MARKERS)

    def _is_excluded(self, message: str) -> bool:
        lc = message.lower()
        return any(marker in lc for marker in self.EXCLUDED_MARKERS)

    def _targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        """
        Returns True when the event's involvedObject is the target pod,
        or when involvedObject is absent / unspecified (treat as global).
        """
        involved_kind = self._involved_kind(event)
        if involved_kind and involved_kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")

        involved_name = self._involved_name(event)
        if pod_name and involved_name and involved_name != pod_name:
            return False

        involved_ns = self._involved_namespace(event)
        if namespace and involved_ns and involved_ns != namespace:
            return False

        return True

    def _is_kube_proxy_event(self, event: dict[str, Any]) -> bool:
        """
        Returns True when the event originates from a kube-proxy component
        or involves a kube-proxy pod.
        """
        component = self._event_component(event)
        if any(marker in component for marker in self.KUBE_PROXY_COMPONENT_MARKERS):
            return True

        involved_name = self._involved_name(event).lower()
        return any(marker in involved_name for marker in self.KUBE_PROXY_POD_MARKERS)

    def _is_kube_proxy_on_node(self, event: dict[str, Any], node_name: str) -> bool:
        """
        Returns True when the kube-proxy event is scoped to the same node
        as the failing pod, using the source.host field.
        """
        if not node_name:
            # No node assignment — accept any kube-proxy iptables event
            return True

        source = event.get("source")
        if isinstance(source, dict):
            host = str(source.get("host") or "").lower()
            if host and node_name.lower() not in host:
                return False

        return True

    def _is_iptables_restore_event(
        self, event: dict[str, Any], pod: dict[str, Any], node_name: str
    ) -> bool:
        """
        Core classifier: returns True when *this* event is an iptables-restore
        failure attributable to the target pod's node.
        """
        reason = self._event_reason(event)
        message = self._event_message(event)

        if not self._has_iptables_marker(message):
            return False

        if self._is_excluded(message):
            return False

        # Direct pod sandbox / network setup failure
        if reason in self.SANDBOX_REASONS and self._targets_pod(event, pod):
            return True

        # kube-proxy node-wide iptables failure on the same node
        if (
            reason in self.KUBE_PROXY_REASONS
            and self._is_kube_proxy_event(event)
            and self._is_kube_proxy_on_node(event, node_name)
        ):
            return True

        return False

    # ------------------------------------------------------------------ #
    # Node condition probe                                                 #
    # ------------------------------------------------------------------ #

    def _node_network_unavailable(self, context: dict[str, Any]) -> bool:
        """
        Returns True when the node hosting the pod reports
        NetworkUnavailable=True via node conditions.
        """
        node_conditions: dict[str, Any] = context.get("node_conditions") or {}
        value = node_conditions.get("NetworkUnavailable")
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "yes", "1")

    # ------------------------------------------------------------------ #
    # Matching event collection                                            #
    # ------------------------------------------------------------------ #

    def _matching_events(
        self, pod: dict[str, Any], timeline: Timeline, node_name: str
    ) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        ordered = self._ordered_events(recent)
        return [
            e for e in ordered if self._is_iptables_restore_event(e, pod, node_name)
        ]

    def _last_success_after(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        since: datetime | None,
    ) -> bool:
        """
        Returns True when a pod-level success event is observed after
        *since*, indicating the iptables issue resolved itself.
        """
        for event in timeline.events:
            if str(event.get("reason") or "") not in self.SUCCESS_REASONS:
                continue
            if not self._targets_pod(event, pod):
                continue
            event_at = self._event_time(event)
            if since is None or event_at is None or event_at >= since:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def matches(self, pod: dict, events: list, context: dict) -> bool:
        phase = get_pod_phase(pod)
        if phase not in ("Pending", "Running"):
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        node_name = str(pod.get("spec", {}).get("nodeName") or "")
        matching = self._matching_events(pod, timeline, node_name)
        if not matching:
            return False

        # If no corroborating node condition, require a minimum number of
        # cumulative occurrences to avoid firing on transient one-offs.
        has_node_condition = self._node_network_unavailable(context)
        total_occurrences = sum(self._occurrences(e) for e in matching)
        if (
            not has_node_condition
            and total_occurrences < self.MIN_OCCURRENCES_WITHOUT_NODE_CONDITION
        ):
            return False

        # Suppress if a success event was observed after the latest failure
        latest_failure_at = self._event_time(matching[-1])
        return not self._last_success_after(pod, timeline, latest_failure_at)

    def explain(self, pod: dict, events: list, context: dict) -> dict[str, Any]:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("IPTablesRestoreFailure requires a Timeline context")

        node_name = str(pod.get("spec", {}).get("nodeName") or "")
        matching = self._matching_events(pod, timeline, node_name)
        if not matching:
            raise ValueError(
                "IPTablesRestoreFailure.explain() called without matching events"
            )

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")

        latest = matching[-1]
        latest_message = self._event_message(latest).strip()
        latest_reason = str(latest.get("reason") or "NetworkNotReady")

        total_occurrences = sum(self._occurrences(e) for e in matching)
        has_node_condition = self._node_network_unavailable(context)

        # Distinguish lock-contention from rule-syntax / module errors for
        # more actionable messaging.
        combined_messages = " ".join(self._event_message(e).lower() for e in matching)
        is_lock_contention = any(
            marker in combined_messages
            for marker in ("xtables lock", "xtables-lock", "lock")
        )
        is_legacy_nft_mismatch = any(
            marker in combined_messages
            for marker in ("iptables-legacy", "iptables-nft", "nft")
        )

        duration_seconds = timeline.duration_between(
            lambda e: self._is_iptables_restore_event(e, pod, node_name)
        )

        # ------------------------------------------------------------------ #
        # Causal chain                                                         #
        # ------------------------------------------------------------------ #
        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_IPTABLES_RULES_PROGRAMMING_FAILED",
                    message=(
                        f"iptables-restore (or ip6tables-restore) could not apply the "
                        f"network plugin's ruleset on node '{node_name or '<unassigned>'}'"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="NODE_DATA_PLANE_RULES_ABSENT",
                    message=(
                        "Required FORWARD / POSTROUTING / NAT rules are missing or "
                        "inconsistent; pod traffic cannot be forwarded or masqueraded"
                    ),
                    role="infrastructure_symptom",
                ),
                Cause(
                    code="POD_NETWORK_SETUP_BLOCKED",
                    message=(
                        f"Pod '{pod_name}' sandbox creation or network connectivity "
                        "setup fails because the node data plane is in a broken state"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        # ------------------------------------------------------------------ #
        # Evidence                                                             #
        # ------------------------------------------------------------------ #
        evidence = [
            f"Pod {namespace}/{pod_name} is {get_pod_phase(pod)} while the node data plane is broken",
            f"Observed {total_occurrences} iptables-restore failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            f"Latest iptables-restore failure reason: {latest_reason}",
            f"Latest iptables-restore failure message: {latest_message}",
        ]

        if node_name:
            evidence.append(f"Pod is assigned to node '{node_name}'")

        if has_node_condition:
            evidence.append(
                f"Node '{node_name or '<unassigned>'}' reports NetworkUnavailable=True, "
                "confirming a node-wide networking outage"
            )

        if is_lock_contention:
            evidence.append(
                "xtables lock contention detected — another process (kube-proxy, "
                "CNI plugin, or iptables-save) is holding the exclusive kernel lock"
            )

        if is_legacy_nft_mismatch:
            evidence.append(
                "iptables-legacy / iptables-nft variant mismatch detected — the "
                "network plugin and the kernel are using incompatible iptables backends"
            )

        if duration_seconds:
            evidence.append(
                f"iptables-restore failures have persisted for "
                f"{duration_seconds / 60:.1f} minutes without recovery"
            )

        evidence.append(
            "No successful pod start or network setup event observed after the latest failure"
        )

        # ------------------------------------------------------------------ #
        # Object evidence                                                      #
        # ------------------------------------------------------------------ #
        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [
                "Pod networking setup is blocked by an iptables-restore failure on the assigned node",
                latest_message,
            ],
        }
        if node_name:
            node_evidence = [
                "Node data plane programming (iptables-restore) is failing; "
                "FORWARD / POSTROUTING rules may be absent or inconsistent"
            ]
            if has_node_condition:
                node_evidence.append("Node condition NetworkUnavailable=True")
            object_evidence[f"node:{node_name}"] = node_evidence

        # ------------------------------------------------------------------ #
        # Confidence                                                           #
        # ------------------------------------------------------------------ #
        # Base confidence driven by signal strength and corroboration
        if has_node_condition:
            confidence = 0.97
        elif total_occurrences >= 5:
            confidence = 0.93
        elif total_occurrences >= 2:
            confidence = 0.88
        else:
            confidence = 0.80

        # ------------------------------------------------------------------ #
        # Likely causes — order from most to least common in production        #
        # ------------------------------------------------------------------ #
        likely_causes = [
            "Another process (a second kube-proxy replica, a CNI plugin, or "
            "iptables-save) is holding the xtables kernel lock, causing "
            "iptables-restore to time out",
            "The node is running a kernel or OS image where iptables-legacy and "
            "iptables-nft coexist but the network plugin uses the wrong backend, "
            "leading to ruleset import errors",
            "A corrupted or incomplete iptables ruleset was written by a previous "
            "network-plugin or kube-proxy crash, leaving the kernel in an "
            "unacceptable state for the restore",
            "The required kernel modules (ip_tables, iptable_filter, iptable_nat, "
            "nf_conntrack) are not loaded or are missing from the node image",
            "kube-proxy or the CNI plugin is running as a non-root user or in a "
            "security context that lacks the NET_ADMIN / NET_RAW capability needed "
            "to program iptables",
            "A node upgrade or live-migration left an orphaned iptables process or "
            "stale lock file (/run/xtables.lock) preventing new writers",
        ]

        # ------------------------------------------------------------------ #
        # Suggested checks                                                     #
        # ------------------------------------------------------------------ #
        suggested_checks = [
            f"kubectl describe pod {pod_name} -n {namespace}",
            f"kubectl get events -n {namespace} --field-selector involvedObject.name={pod_name}",
        ]

        if node_name:
            suggested_checks += [
                f"kubectl describe node {node_name}",
                f"kubectl get pods -n kube-system -o wide | grep kube-proxy | grep {node_name}",
                f"kubectl logs -n kube-system <kube-proxy-pod-on-{node_name}>",
                "# On the node: sudo iptables -L -n -v 2>&1 | head -30",
                "# On the node: sudo iptables-save 2>&1 | head -30",
                "# On the node: sudo cat /run/xtables.lock  (check for a stale lock holder)",
                "# On the node: lsmod | grep -E 'ip_tables|nf_conntrack'",
            ]
        else:
            suggested_checks += [
                "kubectl get pods -n kube-system -o wide | grep kube-proxy",
                "Inspect kube-proxy logs for 'iptables-restore' errors",
                "On the affected node: sudo iptables-save 2>&1 | head -30",
                "On the affected node: lsmod | grep -E 'ip_tables|nf_conntrack'",
            ]

        if is_lock_contention:
            suggested_checks.append(
                "Check for zombie iptables-restore / iptables-save processes: "
                "ps aux | grep iptables"
            )
            suggested_checks.append(
                "Inspect /run/xtables.lock for a stale holder PID and "
                "consider restarting kube-proxy"
            )

        if is_legacy_nft_mismatch:
            suggested_checks.append(
                "Verify that kube-proxy's --iptables-backend flag matches the "
                "node's default iptables binary (iptables-legacy vs iptables-nft)"
            )
            suggested_checks.append(
                "Check 'update-alternatives --list iptables' on the node to see "
                "which backend is active"
            )

        return {
            "root_cause": (
                "iptables-restore failure is preventing pod network setup on the assigned node"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": suggested_checks,
        }
