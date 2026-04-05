from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class HostPortAlreadyAllocatedRule(FailureRule):
    """
    Detects scheduling failures where a requested hostPort tuple is already
    allocated on candidate nodes.

    Real-world behavior:
    - hostPort scheduling is constrained by the uniqueness of
      <hostIP, hostPort, protocol> on each node
    - the default scheduler commonly reports this as
      "didn't have free ports for the requested pod ports" or
      "port is already allocated"
    - this leaves the Pod Pending even though compute resources may otherwise
      be available
    """

    name = "HostPortAlreadyAllocated"
    category = "Scheduling"
    priority = 31
    deterministic = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = ["HostPortConflict", "FailedScheduling"]

    WINDOW_MINUTES = 20
    PORT_ALLOCATED_PATTERNS = (
        "didn't have free ports for the requested pod ports",
        "port is already allocated",
        "ports are already allocated",
        "free ports for the requested pod ports",
    )
    EXPLICIT_PORT_RE = re.compile(
        r"(?:hostport|port)\s*(?::|=)?\s*(\d{1,5})",
        re.IGNORECASE,
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
        recent = timeline.events_within_window(
            self.WINDOW_MINUTES, reason="FailedScheduling"
        )
        if not recent:
            recent = [
                event
                for event in getattr(timeline, "events", [])
                if str(event.get("reason", "")).lower() == "failedscheduling"
            ]

        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _requested_host_ports(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        requested: list[dict[str, Any]] = []
        spec = pod.get("spec", {})

        for container_group in ("initContainers", "containers"):
            for container in spec.get(container_group, []) or []:
                container_name = str(container.get("name", "")).strip() or "<unknown>"
                for port_spec in container.get("ports", []) or []:
                    host_port = port_spec.get("hostPort")
                    if not isinstance(host_port, int):
                        continue
                    requested.append(
                        {
                            "container_name": container_name,
                            "host_port": host_port,
                            "container_port": port_spec.get("containerPort"),
                            "protocol": str(port_spec.get("protocol", "TCP")).upper(),
                            "host_ip": str(port_spec.get("hostIP", "0.0.0.0")),
                        }
                    )

        return requested

    def _allocation_message(self, event: dict[str, Any]) -> bool:
        message = str(event.get("message", "")).lower()
        return any(pattern in message for pattern in self.PORT_ALLOCATED_PATTERNS)

    def _extract_explicit_port(self, message: str) -> int | None:
        for match in self.EXPLICIT_PORT_RE.finditer(message or ""):
            try:
                return int(match.group(1))
            except Exception:
                continue
        return None

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        phase = str(pod.get("status", {}).get("phase", "")).strip()
        if phase and phase != "Pending":
            return None

        if pod.get("spec", {}).get("hostNetwork"):
            return None

        requested = self._requested_host_ports(pod)
        if not requested:
            return None

        recent = self._ordered_recent_events(timeline)
        if not recent:
            return None

        conflict_events = [event for event in recent if self._allocation_message(event)]
        if not conflict_events:
            return None

        requested_ports = {item["host_port"] for item in requested}
        explicit_port = None
        for event in conflict_events:
            explicit_port = self._extract_explicit_port(str(event.get("message", "")))
            if explicit_port is not None:
                break

        matched_requests = [
            item
            for item in requested
            if explicit_port is None or item["host_port"] == explicit_port
        ]
        if not matched_requests:
            return None

        dominant_message = max(
            {str(event.get("message", "")) for event in conflict_events},
            key=lambda message: sum(
                self._occurrences(event)
                for event in conflict_events
                if str(event.get("message", "")) == message
            ),
        )

        total_occurrences = sum(self._occurrences(event) for event in conflict_events)

        return {
            "matched_requests": matched_requests,
            "dominant_message": dominant_message,
            "total_occurrences": total_occurrences,
            "explicit_port": explicit_port,
            "requested_ports": requested_ports,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("HostPortAlreadyAllocated requires a Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("HostPortAlreadyAllocated explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        matched_requests = candidate["matched_requests"]
        total_occurrences = candidate["total_occurrences"]

        request_text = ", ".join(
            f"{item['host_ip']}:{item['host_port']}/{item['protocol']} (container {item['container_name']})"
            for item in matched_requests
        )

        primary = matched_requests[0]
        root_cause = (
            f"Requested hostPort {primary['host_ip']}:{primary['host_port']}/{primary['protocol']} is already allocated on candidate nodes"
            if len(matched_requests) == 1
            else "Requested hostPort bindings are already allocated on candidate nodes"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="HOSTPORT_BINDING_REQUESTED",
                    message="Pod requests node-level hostPort binding",
                    role="workload_context",
                ),
                Cause(
                    code="HOSTPORT_ALREADY_ALLOCATED",
                    message="Requested hostPort tuple is already allocated on candidate node(s)",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_UNSCHEDULABLE",
                    message="Scheduler cannot place the Pod until a node has a free matching hostPort",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod requests hostPort binding(s): {request_text}",
            f"Scheduler reported hostPort allocation conflict {total_occurrences} time(s) within the last {self.WINDOW_MINUTES} minutes",
            f"Representative scheduler message: {candidate['dominant_message']}",
        ]
        if candidate["explicit_port"] is not None:
            evidence.append(
                f"Scheduler message explicitly references allocated port {candidate['explicit_port']}"
            )

        return {
            "rule": self.name,
            "root_cause": root_cause,
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    f"hostPort requests={request_text}",
                    candidate["dominant_message"],
                ]
            },
            "likely_causes": [
                "Another Pod on candidate nodes is already using the same <hostIP, hostPort, protocol> tuple",
                "A DaemonSet or rollout keeps the previous Pod instance bound to the same hostPort",
                "The cluster has too few eligible nodes with that hostPort still free",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get pods -A -o wide",
                "Check which workload is already using the requested hostPort on eligible nodes",
                "Reduce hostPort usage or increase the number of eligible nodes with free ports",
            ],
        }
