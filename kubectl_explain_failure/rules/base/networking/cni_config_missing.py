from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CNIConfigMissingRule(FailureRule):
    """
    Detects kubelet sandbox creation failures caused by missing or
    uninitialized CNI configuration on the node.

    Real-world interpretation:
    - the Pod has already been scheduled to a node
    - kubelet tries to create the Pod sandbox
    - CNI initialization fails because config files were not rendered,
      not discovered, or not yet initialized under /etc/cni/net.d

    Exclusions:
    - generic CNI plugin failures where config exists but plugin execution fails
    - CNI IP exhaustion
    - node-wide NetworkUnavailable conditions handled by node/network rules
    - container runtime outages unrelated to CNI config presence
    """

    name = "CNIConfigMissing"
    category = "Networking"
    priority = 34
    deterministic = True

    blocks = [
        "CNIPluginFailure",
    ]

    requires = {
        "context": ["timeline"],
    }

    phases = ["Pending"]

    WINDOW_MINUTES = 20

    CONFIG_MISSING_MARKERS = (
        "cni config uninitialized",
        "no networks found in /etc/cni/net.d",
        "no valid networks found in /etc/cni/net.d",
        "no cni configuration file in",
        "no cni config",
        "missing cni config",
        "failed to load cni config",
        "failed to find plugin",
        "default network not found",
        "cni plugin not initialized",
        "network plugin is not ready",
    )

    RUNTIME_EXCLUSION_MARKERS = (
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "runtime.v1.runtimeservice",
        "unsupported runtime api version",
        "runtime api version is not supported",
        "containerd.sock",
        "cri-o.sock",
        "connection refused",
    )

    IP_EXHAUSTION_EXCLUSION_MARKERS = (
        "no available ip",
        "no more ips",
        "address pool is exhausted",
        "ip pool exhausted",
        "failed to assign an ip address",
        "ipam",
    )

    NETWORK_UNAVAILABLE_EXCLUSION_MARKERS = (
        "nodenetworkunavailable",
        "routecontroller failed to create a route",
        "failed to create a route to the node",
    )

    def _extract_timestamp(self, event: dict[str, Any]) -> datetime | None:
        raw = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        enumerated = list(enumerate(events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._extract_timestamp(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        pod_name = pod.get("metadata", {}).get("name")
        pod_ns = pod.get("metadata", {}).get("namespace")
        kind = str(involved.get("kind", "")).lower()
        if kind and kind != "pod":
            return False
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if pod_ns and involved.get("namespace") and involved.get("namespace") != pod_ns:
            return False
        return True

    def _is_excluded(self, event: dict[str, Any]) -> bool:
        text = f"{self._event_reason(event)} {self._event_message(event)}"
        return (
            any(marker in text for marker in self.RUNTIME_EXCLUSION_MARKERS)
            or any(marker in text for marker in self.IP_EXHAUSTION_EXCLUSION_MARKERS)
            or any(
                marker in text for marker in self.NETWORK_UNAVAILABLE_EXCLUSION_MARKERS
            )
        )

    def _is_config_missing_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if self._is_excluded(event):
            return False
        if not self._event_targets_pod(event, pod):
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)

        if reason not in {"failedcreatepodsandbox", "cnipluginfailure"}:
            return False
        if "cni" not in message and "network plugin" not in message:
            return False
        return any(marker in message for marker in self.CONFIG_MISSING_MARKERS)

    def _recent_events(
        self,
        timeline: Timeline | None,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if isinstance(timeline, Timeline):
            return self._ordered_events(
                timeline.events_within_window(self.WINDOW_MINUTES)
            )
        return self._ordered_events(events)

    def _matching_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        timeline = context.get("timeline")
        recent_events = self._recent_events(timeline, events)
        return [
            event
            for event in recent_events
            if self._is_config_missing_event(event, pod)
        ]

    def matches(self, pod, events, context) -> bool:
        return bool(self._matching_events(pod, events, context))

    def explain(self, pod, events, context):
        matches = self._matching_events(pod, events, context)
        if not matches:
            raise ValueError(
                "CNIConfigMissing explain() requires a recent config-missing CNI event"
            )

        latest = matches[-1]
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = pod.get("spec", {}).get("nodeName")
        latest_reason = str(latest.get("reason", "FailedCreatePodSandBox"))
        latest_message = str(latest.get("message", "")).strip()

        evidence = [
            "Recent sandbox/network setup event reports missing or uninitialized CNI config",
            f"Latest relevant event reason: {latest_reason}",
            f"Observed {len(matches)} recent CNI config-missing event(s) in the incident window",
        ]
        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod sandbox creation is blocked because node CNI config is missing or uninitialized"
            ]
        }
        if latest_message:
            object_evidence[f"pod:{pod_name}"].append(latest_message)
        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Assigned node failed pod sandbox networking because CNI config was missing or uninitialized"
            ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SANDBOX_INITIALIZATION",
                    message="Kubelet is attempting to initialize Pod sandbox networking",
                    role="runtime_context",
                ),
                Cause(
                    code="CNI_CONFIG_MISSING",
                    message="Node CNI configuration is missing or not initialized",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_NETWORKING_BLOCKED",
                    message="Pod sandbox creation cannot complete until a valid CNI network configuration is present",
                    role="workload_symptom",
                ),
            ]
        )

        suggested_checks = [
            f"kubectl describe pod {pod_name}",
            "Check kubelet logs for missing /etc/cni/net.d configuration errors",
            "Verify the CNI daemonset or bootstrap agent rendered config files on the node",
            "Inspect /etc/cni/net.d on the affected node for a valid network config",
        ]
        if node_name:
            suggested_checks.insert(1, f"kubectl describe node {node_name}")

        likely_causes = [
            "CNI daemonset or bootstrap agent did not render config files into /etc/cni/net.d",
            "Node bootstrapping completed before cluster networking configuration was installed",
            "CNI config files were removed, corrupted, or mounted incorrectly on the node",
            "A node-local networking agent crashed before initializing the default CNI network",
        ]

        return {
            "rule": self.name,
            "root_cause": "CNI configuration is missing on node",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": suggested_checks,
        }
