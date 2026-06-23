from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class SystemOOMKillsPodRule(FailureRule):
    """
    Detects Pods killed by node-level memory exhaustion.

    Real-world behavior:

    Linux may invoke the global OOM killer when the node runs out of memory.
    In that situation a Pod process can be selected as the victim even when
    its own memory limit was not exceeded.

    Typical evidence:

      - kernel OOM killer messages
      - kubelet events mentioning system OOM
      - node MemoryPressure=True
      - multiple workload OOMs on same node
      - container terminated with OOMKilled
      - kernel "Killed process" messages

    Exclusions:

      - ordinary cgroup/container limit OOMs
      - application crashes
      - Evicted Pods
      - image pull failures
    """

    name = "SystemOOMKillsPod"
    category = "Node"
    severity = "High"
    priority = 95
    deterministic = True

    phases = ["Running", "Failed"]

    container_states = [
        "terminated",
        "running",
    ]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "pod",
        ],
    }

    blocks = [
        "OOMKilled",
        "CrashLoopBackOff",
    ]

    WINDOW_MINUTES = 30

    SYSTEM_OOM_MARKERS = (
        "system oom",
        "out of memory",
        "memory cgroup out of memory",
        "oom killer",
        "oom-killer",
        "killed process",
        "invoked oom-killer",
        "memory pressure",
        "systemoom",
    )

    KERNEL_OOM_MARKERS = (
        "killed process",
        "oom killer",
        "oom-killer",
        "invoked oom-killer",
        "out of memory",
    )

    EXCLUDED_MARKERS = (
        "failedmount",
        "failed mount",
        "imagepullbackoff",
        "errimagepull",
        "failedcreatepodsandbox",
        "networkplugin",
        "cni",
        "dns",
    )

    RECOVERY_REASONS = {
        "Started",
        "Pulled",
        "Created",
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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")

        if isinstance(source, dict):
            return str(source.get("component") or "").lower()

        return str(source or "").lower()

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

    def _pod_has_oomkilled_container(
        self,
        pod: dict[str, Any],
    ) -> bool:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []

        for status in statuses:
            state = status.get("state", {}) or {}
            terminated = state.get("terminated", {}) or {}

            if terminated.get("reason") == "OOMKilled":
                return True

            last_state = status.get("lastState", {}) or {}
            last_terminated = last_state.get("terminated", {}) or {}

            if last_terminated.get("reason") == "OOMKilled":
                return True

        return False

    def _node_memory_pressure(
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
            if (
                condition.get("type") == "MemoryPressure"
                and condition.get("status") == "True"
            ):
                return True

        return False

    def _system_oom_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        message = self._message(event).lower()
        reason = self._reason(event).lower()
        component = self._source_component(event)

        if any(x in message for x in self.EXCLUDED_MARKERS):
            return False

        text = f"{reason} {message}"

        if any(marker in text for marker in self.SYSTEM_OOM_MARKERS):
            return True

        if component in {"kernel", "kubelet"}:
            if any(marker in text for marker in self.KERNEL_OOM_MARKERS):
                return True

        return False

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:

        if not self._pod_has_oomkilled_container(pod):
            return None

        node_name = pod.get("spec", {}).get("nodeName")

        oom_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._system_oom_event(e)
        ]

        memory_pressure = self._node_memory_pressure(
            context,
            node_name,
        )

        if not oom_events and not memory_pressure:
            return None

        return {
            "node_name": node_name,
            "oom_events": oom_events,
            "memory_pressure": memory_pressure,
            "oom_count": sum(self._occurrences(e) for e in oom_events),
            "duration_seconds": timeline.duration_between(self._system_oom_event),
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
            raise ValueError("SystemOOMKillsPod requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("SystemOOMKillsPod explain() called without match")

        pod_name = pod.get(
            "metadata",
            {},
        ).get(
            "name",
            "<unknown>",
        )

        namespace = pod.get(
            "metadata",
            {},
        ).get(
            "namespace",
            "default",
        )

        node_name = candidate["node_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_MEMORY_EXHAUSTION",
                    message="Node memory became critically exhausted",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KERNEL_OOM_KILLER_TRIGGERED",
                    message="Linux kernel OOM killer selected workload processes",
                    role="system_failure",
                ),
                Cause(
                    code="POD_TERMINATED_BY_SYSTEM_OOM",
                    message="Pod containers were killed by node-level memory exhaustion",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} contains container(s) terminated with OOMKilled",
        ]

        if node_name:
            evidence.append(f"Pod was running on node {node_name}")

        if candidate["memory_pressure"]:
            evidence.append("Node reports MemoryPressure=True")

        if candidate["oom_events"]:
            evidence.append(
                f"Observed {candidate['oom_count']} system OOM signal occurrence(s)"
            )

            evidence.append(
                f"Representative system OOM event: "
                f"{self._message(candidate['oom_events'][-1])}"
            )

        if candidate["duration_seconds"]:
            evidence.append(
                f"System OOM signals persisted for "
                f"{candidate['duration_seconds'] / 60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": ["Container terminated with reason OOMKilled"]
        }

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Node-level memory exhaustion evidence detected"
            ]

        return {
            "rule": self.name,
            "root_cause": "Node-wide memory exhaustion triggered kernel OOM kills",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node memory capacity exhausted",
                "Memory overcommit across workloads",
                "Large workload spike on the node",
                "Kernel OOM killer selected pod processes as victims",
                "Insufficient memory requests/limits across workloads",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                *([f"kubectl describe node {node_name}"] if node_name else []),
                "kubectl top node",
                "kubectl top pods --all-namespaces",
                "journalctl -u kubelet -n 500",
                "dmesg | grep -i oom",
                "Inspect node MemoryPressure condition",
                "Review node allocatable memory versus workload consumption",
            ],
        }
