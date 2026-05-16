from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CNIIPAMExhaustedRule(FailureRule):
    """
    Detects CNI/IPAM address exhaustion during pod sandbox creation.

    Real-world signals usually come from kubelet events such as
    FailedCreatePodSandBox where the CNI ADD path fails because the plugin
    cannot allocate an address from a node-local pool, subnet, PodCIDR, or
    delegated IPAM plugin. This is common with AWS VPC CNI subnet exhaustion,
    Azure CNI subnet exhaustion, Calico/Cilium IPAM pool exhaustion, and
    Whereabouts/static-range exhaustion.
    """

    name = "CNIIPAMExhausted"
    category = "Networking"
    severity = "High"
    priority = 66
    deterministic = True
    phases = ["Pending"]
    blocks = [
        "CNIPluginFailure",
        "CNIIPExhaustion",
    ]
    requires = {
        "context": ["timeline"],
        "optional_objects": ["node", "pod"],
    }

    window_minutes = 30

    SANDBOX_REASONS = {
        "FailedCreatePodSandBox",
        "FailedCreatePodSandbox",
    }
    CNI_MARKERS = (
        "cni",
        "ipam",
        "aws-cni",
        "azure cni",
        "azure-vnet",
        "calico",
        "cilium",
        "whereabouts",
        "multus",
        "pod network",
        "setup network",
    )
    IPAM_EXHAUSTION_MARKERS = (
        "no available ip",
        "no available ips",
        "no ip addresses available",
        "no available ip addresses",
        "no addresses available",
        "not enough ip addresses",
        "not enough ips",
        "insufficient ip",
        "ip pool exhausted",
        "ippool exhausted",
        "ipam exhausted",
        "address pool exhausted",
        "range is full",
        "range set is exhausted",
        "failed to allocate ip",
        "failed to allocate an ip",
        "failed to assign an ip",
        "failed to assign ip",
        "unable to allocate ip",
        "unable to assign ip",
        "cannot allocate ip",
        "could not allocate ip",
        "subnet has no available ip",
        "subnet is exhausted",
        "available ip address count is 0",
        "assignpodipv4address",
        "insufficientcidrblocks",
        "ipamd",
    )
    EXCLUDED_MARKERS = (
        "cni config uninitialized",
        "no networks found",
        "failed to load cni config",
        "failed to load netconf",
        "no such file or directory",
        "network plugin is not ready",
        "containerd.sock",
        "cri-o.sock",
        "runtime.v1",
        "connection refused",
        "permission denied",
        "unauthorized",
        "forbidden",
        "runtimeclass",
    )
    SUCCESS_REASONS = {
        "Created",
        "Started",
        "Pulled",
        "SandboxChanged",
    }

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _normalized(self, text: str) -> str:
        return " ".join(
            text.lower().replace("-", " ").replace("_", " ").replace(":", " ").split()
        )

    def _has_any(self, text: str, markers: tuple[str, ...]) -> bool:
        normalized = self._normalized(text)
        compact = normalized.replace(" ", "")
        return any(marker in normalized or marker in compact for marker in markers)

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        ts = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(ts, str):
            return None
        try:
            return parse_time(ts)
        except Exception:
            return None

    def _occurrences(self, event: dict[str, Any]) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_ipam_exhaustion_event(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason") or "")
        if reason not in self.SANDBOX_REASONS:
            return False

        message = self._message(event)
        if self._has_any(message, self.EXCLUDED_MARKERS):
            return False

        source = self._source_component(event)
        has_cni_context = source in {"kubelet", "cni"} or self._has_any(
            message, self.CNI_MARKERS
        )
        if not has_cni_context:
            return False

        return self._has_any(message, self.IPAM_EXHAUSTION_MARKERS)

    def _recent_ipam_failures(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_ipam_exhaustion_event(event)
        ]

    def _success_after(self, timeline: Timeline, after: datetime | None) -> bool:
        for event in timeline.events:
            if str(event.get("reason") or "") not in self.SUCCESS_REASONS:
                continue
            event_at = self._event_time(event)
            if after is None or event_at is None or event_at >= after:
                return True
        return False

    def _affected_pod_names(self, events: list[dict[str, Any]]) -> list[str]:
        names = []
        for event in events:
            involved = event.get("involvedObject", {})
            name = involved.get("name")
            if isinstance(name, str) and name and name not in names:
                names.append(name)
        return names

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        failures = self._recent_ipam_failures(timeline)
        if not failures:
            return False

        latest_failure_at = self._event_time(failures[-1])
        if self._success_after(timeline, latest_failure_at):
            return False

        total_occurrences = sum(self._occurrences(event) for event in failures)
        affected_pods = self._affected_pod_names(failures)

        # A single explicit kubelet sandbox failure is enough for the current
        # pod. Multiple occurrences or multiple involved pods strengthen the
        # scale/IP-pool interpretation.
        pod_name = pod.get("metadata", {}).get("name")
        current_pod_seen = not affected_pods or pod_name in affected_pods
        return current_pod_seen or total_occurrences >= 2 or len(affected_pods) >= 2

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CNIIPAMExhausted requires Timeline context")

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")
        node_name = pod.get("spec", {}).get("nodeName", "<unassigned>")

        failures = self._recent_ipam_failures(timeline)
        representative = next(
            (
                event
                for event in reversed(failures)
                if event.get("involvedObject", {}).get("name") == pod_name
            ),
            failures[-1] if failures else {},
        )
        representative_message = self._message(representative)
        representative_reason = str(representative.get("reason") or "<unknown>")
        total_occurrences = sum(self._occurrences(event) for event in failures)
        affected_pods = self._affected_pod_names(failures)
        duration_seconds = timeline.duration_between(self._is_ipam_exhaustion_event)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SANDBOX_NETWORK_SETUP",
                    message="Kubelet attempted to create the Pod sandbox and attach pod networking",
                    role="runtime_context",
                ),
                Cause(
                    code="CNI_IPAM_EXHAUSTED",
                    message="CNI/IPAM could not allocate a pod IP address from the available pool or subnet",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_CREATION_BLOCKED",
                    message="Pod sandbox creation failed because pod networking could not receive an IP address",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod sandbox creation is blocked by CNI/IPAM address exhaustion",
                representative_message,
            ]
        }
        if node_name != "<unassigned>":
            object_evidence[f"node:{node_name}"] = [
                "Assigned node or subnet has no available pod IP addresses"
            ]
        if affected_pods:
            object_evidence["timeline:ipam_failures"] = [
                f"Affected pod(s): {', '.join(affected_pods)}"
            ]

        evidence = [
            f"Pod {namespace}/{pod_name} remains Pending during sandbox creation",
            f"Latest IPAM exhaustion event reason: {representative_reason}",
            f"Latest IPAM exhaustion message: {representative_message}",
            f"Observed {total_occurrences} IPAM allocation failure occurrence(s) within {self.window_minutes} minutes",
            "No successful container start observed after the latest IPAM failure",
        ]
        if node_name != "<unassigned>":
            evidence.append(f"Pod is assigned to node {node_name}")
        if affected_pods:
            evidence.append(f"Timeline affected pod(s): {', '.join(affected_pods)}")
        if duration_seconds:
            evidence.append(
                f"IPAM allocation failures persisted for {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "CNI/IPAM address pool exhausted during pod sandbox creation",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Subnet or secondary IP range has no free pod IP addresses",
                "Node-local CNI warm IP target or ENI/IP capacity is exhausted",
                "Calico, Cilium, Azure CNI, AWS VPC CNI, or Whereabouts IPAM pool is depleted",
                "Pods per node or subnet sizing is too small for current workload density",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get events --sort-by=.lastTimestamp",
                "Check CNI daemon logs on the assigned node for IPAM allocation errors",
                "Inspect subnet, PodCIDR, secondary range, ENI, or IP pool free-address capacity",
                "Add pod IP capacity, expand the subnet/IP pool, or reduce pod density on affected nodes",
            ],
        }
