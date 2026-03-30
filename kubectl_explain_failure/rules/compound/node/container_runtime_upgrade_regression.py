from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ContainerRuntimeUpgradeRegressionRule(FailureRule):
    """
    Detects a pod blocked by a CRI compatibility failure that begins shortly
    after the node's kubelet/runtime startup or re-registration window.

    Real-world interpretation:
    - kubelet or the node emits a recent startup / re-registration signal
    - shortly afterward, kubelet begins repeated runtime API/version mismatch
      failures on that same node
    - the node is currently NotReady/Unknown with an explicit CRI mismatch
      message, indicating the incompatibility is still active
    - this approximates a bad kubelet/runtime upgrade or restart rollout,
      which is more specific than a generic version mismatch snapshot

    Exclusions:
    - pure runtime outages where kubelet cannot reach the socket at all
    - CNI / network plugin failures
    - stale historical startup signals that are far from the current failures
    """

    name = "ContainerRuntimeUpgradeRegression"
    category = "Compound"
    priority = 67
    deterministic = True

    blocks = [
        "ContainerRuntimeVersionMismatch",
        "ContainerRuntimeUnavailable",
        "NodeNotReady",
        "ContainerRuntimeStartFailure",
        "FailedScheduling",
    ]

    requires = {
        "objects": ["node"],
        "context": ["timeline"],
    }

    supported_phases = {"Pending", "Running", "Unknown"}

    RECENT_WINDOW_MINUTES = 20
    MAX_DELAY_AFTER_START = timedelta(minutes=10)
    FAILURE_CLUSTER_WINDOW = timedelta(minutes=10)
    MIN_FAILURE_OCCURRENCES = 2

    VERSION_MARKERS = (
        "unknown service runtime.v1.runtimeservice",
        "unknown service runtime.v1alpha2.runtimeservice",
        "runtime api version is not supported",
        "unsupported runtime api version",
        "container runtime version is incompatible",
        "cri v1 runtime api is not implemented",
        "runtime service does not support",
        "unsupported service runtime.v1",
        "unsupported service runtime.v1alpha2",
    )

    STATUS_MARKERS = (
        "failed to get runtime status",
        "failed to create pod sandbox",
        "container runtime status check may not have completed yet",
        "runtime service failed",
        "rpc error: code = unimplemented",
    )

    OUTAGE_EXCLUSION_MARKERS = (
        "container runtime is down",
        "container runtime is not running",
        "failed to connect to container runtime",
        "connection refused",
        "rpc error: code = unavailable",
        "dial unix",
        "no such file or directory",
    )

    NETWORK_EXCLUSION_MARKERS = (
        "network plugin not ready",
        "cni config uninitialized",
        "network is unavailable",
        "pod network",
        "failed to assign an ip address",
        "ipam",
    )

    WAITING_REASONS = {
        "ContainerCreating",
        "CreateContainerError",
        "RunContainerError",
        "CrashLoopBackOff",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _extract_start_time(self, event: dict[str, Any]) -> datetime | None:
        return self._parse_timestamp(
            event.get("eventTime")
            or event.get("firstTimestamp")
            or event.get("lastTimestamp")
            or event.get("timestamp")
        )

    def _extract_end_time(self, event: dict[str, Any]) -> datetime | None:
        return self._parse_timestamp(
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        enumerated = list(enumerate(timeline.raw_events))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._extract_start_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _candidate_node(
        self, pod: dict[str, Any], node_objs: dict[str, dict[str, Any]]
    ) -> tuple[str, dict[str, Any]] | None:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return assigned_node, node_objs[assigned_node]
        if len(node_objs) == 1:
            return next(iter(node_objs.items()))
        return None

    def _ready_condition(self, node: dict[str, Any]) -> dict[str, Any] | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "Ready":
                return cond
        return None

    def _condition_points_to_version_mismatch(self, node: dict[str, Any]) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        status = str(cond.get("status", ""))
        message = str(cond.get("message", "")).lower()
        if status not in {"False", "Unknown"}:
            return False

        if not any(marker in message for marker in self.VERSION_MARKERS):
            return False

        return (
            any(marker in message for marker in self.STATUS_MARKERS)
            or "runtime" in message
        )

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_targets_node(self, event: dict[str, Any], node_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if str(involved.get("kind", "")).lower() == "node" and (
                involved.get("name") == node_name
            ):
                return True
            if involved.get("nodeName") == node_name:
                return True
        return node_name.lower() in self._event_message(event)

    def _event_targets_pod(self, event: dict[str, Any], pod_name: str) -> bool:
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            if str(involved.get("kind", "")).lower() == "pod" and (
                involved.get("name") == pod_name
            ):
                return True
        return pod_name.lower() in self._event_message(event)

    def _has_exclusion_markers(self, text: str) -> bool:
        lowered = text.lower()
        return any(
            marker in lowered for marker in self.OUTAGE_EXCLUSION_MARKERS
        ) or any(marker in lowered for marker in self.NETWORK_EXCLUSION_MARKERS)

    def _is_start_signal(self, event: dict[str, Any], node_name: str) -> bool:
        component = self._event_component(event)
        if component and component not in {"kubelet", "node-controller"}:
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)
        text = f"{reason} {message}"

        if self._has_exclusion_markers(text):
            return False

        if reason in {"starting", "registerednode"}:
            return True

        if component == "kubelet" and "starting kubelet" in message:
            return True

        return (
            self._event_targets_node(event, node_name) and "registered node" in message
        )

    def _is_mismatch_signal(
        self,
        event: dict[str, Any],
        pod_name: str,
        node_name: str,
    ) -> bool:
        component = self._event_component(event)
        if component and component not in {"kubelet", "node-controller"}:
            return False

        reason = self._event_reason(event)
        message = self._event_message(event)
        text = f"{reason} {message}"

        if self._has_exclusion_markers(text):
            return False
        if not any(marker in text for marker in self.VERSION_MARKERS):
            return False

        if not (
            self._event_targets_pod(event, pod_name)
            or self._event_targets_node(event, node_name)
        ):
            return False

        if reason in {"failedcreatepodsandbox", "failed", "containerruntimeunhealthy"}:
            return True

        return any(marker in text for marker in self.STATUS_MARKERS)

    def _event_occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _pod_currently_impacted(self, pod: dict[str, Any]) -> bool:
        if pod.get("status", {}).get("phase") == "Pending":
            return True

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") in self.WAITING_REASONS:
                return True
        return False

    def _correlation(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        node_name: str,
        node: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not self._condition_points_to_version_mismatch(node):
            return None

        if not self._pod_currently_impacted(pod):
            return None

        recent_events = timeline.events_within_window(self.RECENT_WINDOW_MINUTES)
        ordered = self._ordered_events(
            Timeline(recent_events, relative_to=timeline.relative_to)
        )

        pod_name = pod.get("metadata", {}).get("name", "")
        if not pod_name:
            return None

        start_events = []
        mismatch_events = []
        for event in ordered:
            start_time = self._extract_start_time(event)
            if start_time is None:
                continue
            if self._is_start_signal(event, node_name):
                start_events.append((start_time, event))
            if self._is_mismatch_signal(event, pod_name, node_name):
                mismatch_events.append((start_time, event))

        if not start_events or not mismatch_events:
            return None

        for mismatch_index, (mismatch_start, mismatch_event) in enumerate(
            mismatch_events
        ):
            precursor_candidates = [
                (start_time, start_event)
                for start_time, start_event in start_events
                if start_time <= mismatch_start
                and (mismatch_start - start_time) <= self.MAX_DELAY_AFTER_START
            ]
            if not precursor_candidates:
                continue

            start_time, start_event = max(
                precursor_candidates, key=lambda item: item[0]
            )
            cluster_deadline = mismatch_start + self.FAILURE_CLUSTER_WINDOW
            total_occurrences = 0
            cluster_end = self._extract_end_time(mismatch_event) or mismatch_start

            for candidate_start, candidate_event in mismatch_events[mismatch_index:]:
                if candidate_start > cluster_deadline:
                    break
                total_occurrences += self._event_occurrences(candidate_event)
                candidate_end = (
                    self._extract_end_time(candidate_event) or candidate_start
                )
                if candidate_end > cluster_end:
                    cluster_end = candidate_end

            if total_occurrences < self.MIN_FAILURE_OCCURRENCES:
                continue

            return {
                "start_event": start_event,
                "start_time": start_time,
                "first_mismatch": mismatch_event,
                "first_mismatch_time": mismatch_start,
                "failure_occurrences": total_occurrences,
                "cluster_end": cluster_end,
            }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        candidate = self._candidate_node(pod, node_objs)
        if candidate is None:
            return False

        node_name, node = candidate
        return self._correlation(pod, timeline, node_name, node) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        node_objs = context.get("objects", {}).get("node", {})
        candidate = self._candidate_node(pod, node_objs)
        if not isinstance(timeline, Timeline) or candidate is None:
            raise ValueError(
                "ContainerRuntimeUpgradeRegression requires node and timeline"
            )

        node_name, node = candidate
        correlation = self._correlation(pod, timeline, node_name, node)
        if correlation is None:
            raise ValueError(
                "ContainerRuntimeUpgradeRegression explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        cond = self._ready_condition(node) or {}
        ready_reason = str(cond.get("reason", "KubeletNotReady"))
        start_reason = str(correlation["start_event"].get("reason", "Starting"))
        mismatch_reason = str(
            correlation["first_mismatch"].get("reason", "FailedCreatePodSandBox")
        )
        mismatch_message = str(correlation["first_mismatch"].get("message", "")).strip()

        delay_seconds = (
            correlation["first_mismatch_time"] - correlation["start_time"]
        ).total_seconds()
        window_seconds = (
            correlation["cluster_end"] - correlation["first_mismatch_time"]
        ).total_seconds()

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_RUNTIME_RECENTLY_RESTARTED_OR_REREGISTERED",
                    message="Timeline shows a recent kubelet or node startup/re-registration signal before CRI incompatibility began",
                    role="temporal_context",
                ),
                Cause(
                    code="POST_UPGRADE_RUNTIME_REGRESSION",
                    message="A recent runtime or kubelet rollout introduced a CRI compatibility regression on the node",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_RUNTIME_API_NEGOTIATION_FAILS",
                    message="Kubelet can reach the runtime but repeated CRI API/version negotiation fails after the rollout window",
                    role="control_loop",
                ),
                Cause(
                    code="POD_BLOCKED_BY_POST_UPGRADE_CRI_MISMATCH",
                    message="The pod remains blocked because sandbox creation and runtime operations fail after the upgrade regression",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Recent container runtime upgrade or restart introduced a CRI compatibility regression on the node",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Node Ready condition currently reports a container runtime API/version mismatch",
                f"Recent node startup or re-registration signal observed on {node_name} (reason={start_reason})",
                f"CRI mismatch failures began {delay_seconds / 60:.1f} minutes after that startup window",
                f"Mismatch failures repeated {correlation['failure_occurrences']} time(s) within {window_seconds / 60:.1f} minutes",
                f"First post-start mismatch event reason: {mismatch_reason}",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    f"Ready condition indicates CRI incompatibility (reason={ready_reason})",
                    "Node emitted a recent startup or re-registration signal before mismatch failures began",
                ],
                f"pod:{pod_name}": [
                    "Pod is assigned to a node where CRI mismatch failures started immediately after a restart or upgrade window",
                    *([mismatch_message] if mismatch_message else []),
                ],
            },
            "likely_causes": [
                "containerd or CRI-O was upgraded to a CRI API level kubelet on this node does not support",
                "Kubelet was upgraded or restarted against an older runtime that does not implement the expected CRI service",
                "A node maintenance or package rollout restarted kubelet/runtime components in an incompatible combination",
                "The runtime shim or CRI plugin changed during the rollout and now fails kubelet API negotiation",
            ],
            "suggested_checks": [
                f"kubectl describe node {node_name}",
                f"kubectl describe pod {pod_name}",
                "Compare kubelet and container runtime versions on the node and recent upgrade history",
                "Inspect kubelet and container runtime logs around the startup window and first CRI mismatch failures",
            ],
        }
