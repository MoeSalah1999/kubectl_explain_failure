from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class KubeletRestartLoopRule(FailureRule):
    """
    Detects repeated kubelet restarts that cause node readiness flapping.

    Real-world interpretation:
    - kubelet emits repeated startup or re-registration signals
    - node-controller alternates between NodeReady and NodeNotReady
    - the same node keeps flapping within a short operational window
    - this is broader than one transient NodeNotReady event but narrower
      than generic node instability because it requires kubelet restart
      evidence plus readiness oscillation

    Exclusions:
    - certificate validity failures (covered by KubeletCertificateExpired /
      NodeClockSkewDetected)
    - heartbeat-loss-only outages without restart evidence
    - CRI/runtime outages or API/version mismatch signatures
    """

    name = "KubeletRestartLoop"
    category = "Compound"
    priority = 64
    deterministic = True

    blocks = [
        "KubeletNotResponding",
        "NodeNotReady",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    supported_phases = {"Pending", "Running", "Unknown"}

    WINDOW_MINUTES = 15
    MIN_START_SIGNALS = 2
    MIN_NOTREADY_SIGNALS = 2
    MIN_READY_SIGNALS = 1
    MIN_DURATION_SECONDS = 60

    HEARTBEAT_ONLY_MARKERS = (
        "kubelet stopped posting node status",
        "node status is unknown",
        "node status unknown",
        "heartbeat",
        "node lease",
    )

    CERTIFICATE_MARKERS = (
        "x509",
        "certificate has expired",
        "certificate is not yet valid",
        "not yet valid",
        "certificate signed by unknown authority",
    )

    RUNTIME_MARKERS = (
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "connection refused",
        "containerd.sock",
        "cri-o.sock",
        "runtime.v1.runtimeservice",
        "unknown service runtime.v1",
        "unsupported runtime api version",
        "runtime api version is not supported",
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

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        enumerated = list(enumerate(timeline.raw_events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._extract_timestamp(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _candidate_nodes(
        self, pod: dict, node_objs: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return {assigned_node: node_objs[assigned_node]}
        return node_objs

    def _ready_condition(self, node: dict[str, Any]) -> dict[str, Any] | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "Ready":
                return cond
        return None

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _has_excluded_markers(self, text: str) -> bool:
        lowered = text.lower()
        return (
            any(marker in lowered for marker in self.HEARTBEAT_ONLY_MARKERS)
            or any(marker in lowered for marker in self.CERTIFICATE_MARKERS)
            or any(marker in lowered for marker in self.RUNTIME_MARKERS)
        )

    def _is_start_signal(self, event: dict[str, Any]) -> bool:
        reason = self._event_reason(event)
        message = self._event_message(event)
        component = self._event_component(event)

        if component and component != "kubelet":
            return False
        if self._has_excluded_markers(message):
            return False

        if reason in {"starting", "registerednode"}:
            return True

        return "starting kubelet" in message or "registered node" in message

    def _is_ready_signal(self, event: dict[str, Any]) -> bool:
        reason = self._event_reason(event)
        message = self._event_message(event)
        return reason == "nodeready" or "status is now: nodeready" in message

    def _is_notready_signal(self, event: dict[str, Any]) -> bool:
        reason = self._event_reason(event)
        message = self._event_message(event)
        if self._has_excluded_markers(message):
            return False
        return reason == "nodenotready" or "status is now: nodenotready" in message

    def _classify(self, event: dict[str, Any]) -> str | None:
        if self._is_start_signal(event):
            return "start"
        if self._is_ready_signal(event):
            return "ready"
        if self._is_notready_signal(event):
            return "notready"
        return None

    def _relevant_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        ordered = self._ordered_events(
            Timeline(recent, relative_to=timeline.relative_to)
        )

        relevant = []
        for event in ordered:
            category = self._classify(event)
            if category is None:
                continue
            relevant.append(event)
        return relevant

    def _collapsed_sequence(self, events: list[dict[str, Any]]) -> list[str]:
        sequence: list[str] = []
        for event in events:
            category = self._classify(event)
            if category is None:
                continue
            if not sequence or sequence[-1] != category:
                sequence.append(category)
        return sequence

    def _duration_seconds(self, events: list[dict[str, Any]]) -> float:
        if len(events) < 2:
            return 0.0
        first_ts = self._extract_timestamp(events[0])
        last_ts = self._extract_timestamp(events[-1])
        if first_ts is None or last_ts is None:
            return 0.0
        return (last_ts - first_ts).total_seconds()

    def _condition_recent(self, node: dict[str, Any], timeline: Timeline) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        transition = cond.get("lastTransitionTime")
        if not isinstance(transition, str):
            return False

        try:
            last_transition = parse_time(transition)
        except Exception:
            return False

        reference = timeline._reference_time()
        return (reference - last_transition).total_seconds() <= self.WINDOW_MINUTES * 60

    def _condition_excluded(self, node: dict[str, Any]) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        reason = str(cond.get("reason", ""))
        message = str(cond.get("message", ""))
        text = f"{reason} {message}"
        return self._has_excluded_markers(text)

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        if not candidate_nodes:
            return False

        relevant_events = self._relevant_events(timeline)
        if len(relevant_events) < 4:
            return False

        start_count = sum(
            1 for event in relevant_events if self._is_start_signal(event)
        )
        ready_count = sum(
            1 for event in relevant_events if self._is_ready_signal(event)
        )
        notready_count = sum(
            1 for event in relevant_events if self._is_notready_signal(event)
        )

        if start_count < self.MIN_START_SIGNALS:
            return False
        if ready_count < self.MIN_READY_SIGNALS:
            return False
        if notready_count < self.MIN_NOTREADY_SIGNALS:
            return False

        sequence = self._collapsed_sequence(relevant_events)
        if len(sequence) < 4:
            return False
        if "ready" not in sequence or "notready" not in sequence:
            return False

        flapping_detected = False
        for idx in range(2, len(sequence)):
            if sequence[idx] == "notready" and sequence[idx - 1] == "ready":
                flapping_detected = True
                break
        if not flapping_detected:
            return False

        duration = self._duration_seconds(relevant_events)
        if duration < self.MIN_DURATION_SECONDS:
            return False

        for node in candidate_nodes.values():
            if self._condition_excluded(node):
                continue
            if self._condition_recent(node, timeline):
                return True

        return False

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = next(iter(candidate_nodes), "<node>")
        node = candidate_nodes.get(node_name, {})
        cond = self._ready_condition(node) or {}
        ready_status = str(cond.get("status", "Unknown"))
        ready_reason = str(cond.get("reason", "KubeletNotReady"))

        relevant_events = (
            self._relevant_events(timeline) if isinstance(timeline, Timeline) else []
        )
        sequence = self._collapsed_sequence(relevant_events)
        start_count = sum(
            1 for event in relevant_events if self._is_start_signal(event)
        )
        duration = self._duration_seconds(relevant_events)

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPEATED_KUBELET_STARTUP_SIGNALS",
                    message=f"Timeline contains {start_count} kubelet startup or re-registration signals",
                    role="temporal_context",
                ),
                Cause(
                    code="KUBELET_RESTART_LOOP",
                    message="Kubelet repeatedly restarted and destabilized node readiness",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="NODE_READY_FLAPPING",
                    message="Node alternated between Ready and NotReady as kubelet restarted",
                    role="control_loop",
                ),
                Cause(
                    code="WORKLOAD_IMPACTED_BY_NODE_AGENT_INSTABILITY",
                    message="Workload is affected because the node agent is repeatedly restarting",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Kubelet restart loop is causing node readiness flapping",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Node Ready condition currently {ready_status} (reason={ready_reason})",
                f"Kubelet startup or re-registration signals observed {start_count} times within {self.WINDOW_MINUTES} minutes",
                f"Node readiness sequence flapped as: {' -> '.join(sequence)}",
                f"Readiness flapping persisted for {duration/60:.1f} minutes",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    f"Ready condition={ready_status} reason={ready_reason}",
                    "Kubelet startup and node readiness events repeatedly alternated",
                ],
                f"pod:{pod_name}": [
                    "Pod is assigned to a node with repeated kubelet restart signals"
                ],
            },
            "likely_causes": [
                "systemd or the host watchdog is repeatedly restarting kubelet",
                "kubelet crashes shortly after startup because of local configuration or dependency issues",
                "node pressure or host instability causes kubelet to repeatedly restart and re-register",
                "frequent kubelet restarts are causing readiness to flap faster than workloads can stabilize",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                "Check kubelet service restart count and recent journal logs on the node",
                "Inspect recent NodeReady/NodeNotReady transitions and node event ordering",
                f"kubectl describe pod {pod_name}",
            ],
        }
