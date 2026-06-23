from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CPUCFSQuotaThrottlingProbeFailureRule(FailureRule):
    """
    Detects probe failures caused by Linux CPU CFS quota throttling.

    Real-world behavior:

    Kubernetes CPU limits are enforced via Linux CFS quotas.

    When a workload is heavily CPU throttled:

      - readiness probes timeout
      - liveness probes timeout
      - startup probes timeout
      - containers may restart
      - application appears unhealthy despite functioning correctly

    This rule only fires when probe failures are present and
    independent evidence indicates CPU throttling.

    Excludes:

      - OOM conditions
      - DNS failures
      - image pull failures
      - CNI failures
      - application crashes
      - node resource pressure
    """

    name = "CPUCFSQuotaThrottlingProbeFailure"
    category = "Node"
    severity = "High"
    priority = 88
    deterministic = True

    phases = ["Running"]

    container_states = [
        "running",
        "terminated",
        "waiting",
    ]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "node",
        ],
    }

    blocks = [
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
    ]

    WINDOW_MINUTES = 30

    PROBE_FAILURE_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "probe failed",
        "probe error",
        "context deadline exceeded",
        "request canceled while waiting",
        "client.timeout exceeded",
        "timed out",
    )

    CPU_THROTTLE_MARKERS = (
        "cpu throttling",
        "throttled",
        "cfs quota",
        "cfs throttling",
        "cpu.cfs_quota_us",
        "cpu limit reached",
        "cpu quota exceeded",
        "container cpu throttled",
    )

    EXCLUDED_MARKERS = (
        "oomkilled",
        "out of memory",
        "failedmount",
        "imagepullbackoff",
        "errimagepull",
        "failedcreatepodsandbox",
        "networkplugin",
        "cni",
        "dns",
        "lookup ",
        "no such host",
        "connection refused",
        "crashloopbackoff",
    )

    RECOVERY_REASONS = {
        "Started",
        "Pulled",
        "Created",
        "Killing",
    }

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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _targets_current_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject", {})

        if not isinstance(involved, dict):
            return True

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

    def _is_probe_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False

        message = self._message(event).lower()

        if any(x in message for x in self.EXCLUDED_MARKERS):
            return False

        return any(marker in message for marker in self.PROBE_FAILURE_MARKERS)

    def _is_cpu_throttle_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        return any(marker in text for marker in self.CPU_THROTTLE_MARKERS)

    def _container_has_cpu_limit(
        self,
        pod: dict[str, Any],
    ) -> bool:
        containers = pod.get("spec", {}).get("containers", [])

        for container in containers:
            limits = container.get("resources", {}).get("limits", {})

            if "cpu" in limits:
                return True

        return False

    def _node_under_cpu_pressure(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> bool:
        if not node_name:
            return False

        node = context.get("objects", {}).get("node", {}).get(node_name)

        if not isinstance(node, dict):
            return False

        for condition in node.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == "Ready" and condition.get("status") == "False":
                return True

        return False

    def _recovered_after(
        self,
        timeline: Timeline,
        failure_time: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if self._reason(event) not in self.RECOVERY_REASONS:
                continue

            ts = self._event_time(event)

            if failure_time is None or ts is None or ts >= failure_time:
                return True

        return False

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:

        if not self._container_has_cpu_limit(pod):
            return None

        probe_failures = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._is_probe_failure(e, pod)
        ]

        if not probe_failures:
            return None

        throttle_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._is_cpu_throttle_event(e)
        ]

        if not throttle_events:
            return None

        node_name = pod.get("spec", {}).get("nodeName")

        if self._node_under_cpu_pressure(
            context,
            node_name,
        ):
            return None

        latest_probe = probe_failures[-1]
        latest_probe_time = self._event_time(latest_probe)

        if self._recovered_after(
            timeline,
            latest_probe_time,
        ):
            return None

        return {
            "node_name": node_name,
            "probe_failures": probe_failures,
            "throttle_events": throttle_events,
            "probe_count": sum(self._occurrences(e) for e in probe_failures),
            "throttle_count": sum(self._occurrences(e) for e in throttle_events),
            "duration_seconds": timeline.duration_between(
                lambda e: self._is_probe_failure(e, pod)
                or self._is_cpu_throttle_event(e)
            ),
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError(
                "CPUCFSQuotaThrottlingProbeFailure requires Timeline context"
            )

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "CPUCFSQuotaThrottlingProbeFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        node_name = candidate["node_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CPU_CFS_QUOTA_LIMITING",
                    message="Linux CFS quota enforcement throttled container CPU execution",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="PROBE_EXECUTION_DELAYED",
                    message="Probe handlers could not execute within configured deadlines",
                    role="intermediate_failure",
                ),
                Cause(
                    code="KUBELET_PROBE_FAILURE",
                    message="Kubelet interpreted delayed probe responses as failures",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (f"Observed " f"{candidate['probe_count']} probe failure occurrence(s)"),
            (
                f"Observed "
                f"{candidate['throttle_count']} CPU throttling occurrence(s)"
            ),
            "Container defines CPU limits enabling CFS quota enforcement",
        ]

        if node_name:
            evidence.append(f"Pod is running on node {node_name}")

        if candidate["duration_seconds"]:
            evidence.append(
                f"Probe failures and throttling persisted for "
                f"{candidate['duration_seconds'] / 60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": ["Probe failures correlated with CPU throttling signals"]
        }

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Node healthy; workload-level throttling detected"
            ]

        return {
            "rule": self.name,
            "root_cause": "CPU CFS quota throttling caused kubelet probe failures",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "CPU limit configured too low",
                "Workload burst exceeds allotted CPU quota",
                "Probe handlers starved by CPU throttling",
                "Aggressive CFS quota enforcement",
                "CPU-intensive background workload inside container",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl top pod",
                "Inspect CPU limits versus observed usage",
                "Check container_cpu_cfs_throttled_seconds_total",
                "Check container_cpu_cfs_throttled_periods_total",
                "Review liveness/readiness/startup probe timeout settings",
                "Temporarily raise CPU limits and observe probe behavior",
            ],
        }
