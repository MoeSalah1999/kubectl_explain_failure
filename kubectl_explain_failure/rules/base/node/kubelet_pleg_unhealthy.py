from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class KubeletPLEGUnhealthyRule(FailureRule):
    """
    Detects kubelet Pod Lifecycle Event Generator (PLEG) failures.

    Real-world behavior:

    - kubelet reports "PLEG is not healthy"
    - kubelet may stop syncing pods
    - container state updates become stale
    - pods become stuck in Creating, Terminating or Unknown states
    - node often transitions NotReady
    - commonly caused by container runtime stalls or node overload

    Excludes:

    - generic image pull failures
    - sandbox creation failures
    - network failures
    - DNS failures
    - workload-specific crashes
    """

    name = "KubeletPLEGUnhealthy"
    category = "Node"
    severity = "High"
    priority = 91
    deterministic = True

    phases = ["Pending", "Running", "Unknown"]

    container_states = [
        "waiting",
        "running",
        "terminated",
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
        "NodeNotReady",
    ]

    WINDOW_MINUTES = 30

    PLEG_MARKERS = (
        "pleg is not healthy",
        "pleg was last seen active",
        "pleg unhealthy",
        "pod lifecycle event generator",
        "skipping pod synchronization",
        "skipping pod sync",
    )

    PLEG_RUNTIME_MARKERS = (
        "failed to get pod status",
        "failed to get status for pod",
        "container runtime status check may not have completed yet",
        "runtime network not ready",
    )

    RUNTIME_RESTART_MARKERS = (
        "container runtime is down",
        "runtime service unavailable",
        "container runtime unavailable",
        "container runtime restarted",
        "kubelet detected runtime restart",
        "containerd restarted",
        "container runtime status check failed",
        "runtime ready=false",
    )

    RECOVERY_MARKERS = (
        "pleg has resumed",
        "pleg is healthy",
    )

    WORKLOAD_EXCLUSIONS = (
        "imagepullbackoff",
        "errimagepull",
        "failed to pull image",
        "dns",
        "no such host",
        "failed to create pod sandbox",
        "networkplugin",
        "network plugin",
        "cni",
        "certificate",
        "tls",
    )

    def _runtime_restart_present(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        for event in events:
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.RUNTIME_RESTART_MARKERS):
                return True

        return False

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

    def _ordered_recent_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
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

    def _event_targets_node(
        self,
        event: dict[str, Any],
        node_name: str | None,
    ) -> bool:
        if not node_name:
            return True

        involved = event.get("involvedObject", {})

        if isinstance(involved, dict):
            if involved.get("name") == node_name:
                return True

        return node_name.lower() in self._message(event).lower()

    def _is_pleg_event(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        if any(marker in text for marker in self.WORKLOAD_EXCLUSIONS):
            return False

        return any(marker in text for marker in self.PLEG_MARKERS)

    def _is_runtime_corroboration(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

        return any(marker in text for marker in self.PLEG_RUNTIME_MARKERS)

    def _node_not_ready_signal(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> str | None:
        if not node_name:
            return None

        node = (
            context.get(
                "objects",
                {},
            )
            .get(
                "node",
                {},
            )
            .get(node_name)
        )

        if not isinstance(node, dict):
            return None

        for condition in node.get(
            "status",
            {},
        ).get(
            "conditions",
            [],
        ):
            if condition.get("type") == "Ready" and condition.get("status") != "True":
                return f"Node {node_name} is NotReady"

        return None

    def _recovered_after(
        self,
        timeline: Timeline,
        failure_time: datetime | None,
    ) -> bool:
        for event in timeline.events:
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if not any(marker in text for marker in self.RECOVERY_MARKERS):
                continue

            event_time = self._event_time(event)

            if failure_time is None or event_time is None or event_time >= failure_time:
                return True

        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        node_name = pod.get("spec", {}).get("nodeName")

        recent_events = self._ordered_recent_events(timeline)
        #
        # Runtime restart is a stronger root cause than PLEG.
        # PLEG often becomes unhealthy after a runtime restart.
        #
        if self._runtime_restart_present(recent_events):
            return None

        pleg_events = [
            event
            for event in recent_events
            if self._is_pleg_event(event)
            and self._event_targets_node(
                event,
                node_name,
            )
        ]

        if not pleg_events:
            return None

        #
        # Runtime restart/runtime outage rules own those failures.
        #
        if self._runtime_restart_present(recent_events):
            return None

        runtime_events = [
            event for event in recent_events if self._is_runtime_corroboration(event)
        ]

        node_signal = self._node_not_ready_signal(
            context,
            node_name,
        )

        latest_failure = self._event_time(pleg_events[-1])

        if self._recovered_after(
            timeline,
            latest_failure,
        ):
            return None

        duration_seconds = timeline.duration_between(
            lambda event: (
                self._is_pleg_event(event) or self._is_runtime_corroboration(event)
            )
        )

        return {
            "node_name": node_name,
            "pleg_events": pleg_events,
            "runtime_events": runtime_events,
            "node_signal": node_signal,
            "duration_seconds": duration_seconds,
            "representative_message": self._message(pleg_events[-1]),
            "occurrences": sum(self._occurrences(event) for event in pleg_events),
        }

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        candidate = self._best_candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("KubeletPLEGUnhealthy explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        node_name = candidate["node_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="KUBELET_PLEG_UNHEALTHY",
                    message=("Kubelet Pod Lifecycle Event Generator " "is unhealthy"),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_CANNOT_TRACK_POD_STATE",
                    message=(
                        "Kubelet cannot reliably observe " "container lifecycle events"
                    ),
                    role="runtime_failure",
                ),
                Cause(
                    code="POD_STATE_RECONCILIATION_STALLED",
                    message=("Pod lifecycle processing " "becomes stalled"),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Representative PLEG failure: {candidate['representative_message']}",
            (f"Observed {candidate['occurrences']} " f"PLEG failure occurrence(s)"),
        ]

        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")

        if candidate["node_signal"]:
            evidence.append(candidate["node_signal"])

        if candidate["duration_seconds"]:
            evidence.append(
                f"PLEG unhealthy state persisted for "
                f"{candidate['duration_seconds'] / 60:.1f} minutes"
            )

        confidence = 0.98

        if candidate["runtime_events"] or candidate["node_signal"]:
            confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": "Kubelet PLEG is unhealthy",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [candidate["representative_message"]],
                **(
                    {f"node:{node_name}": ["PLEG unhealthy on node"]}
                    if node_name
                    else {}
                ),
            },
            "likely_causes": [
                "containerd is stalled",
                "CRI communication is hanging",
                "node resource starvation",
                "storage subsystem latency",
                "kubelet runtime synchronization failure",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                *([f"kubectl describe node {node_name}"] if node_name else []),
                "journalctl -u kubelet",
                "systemctl status containerd",
                "crictl ps -a",
                "crictl pods",
                "kubectl get events --sort-by=.lastTimestamp",
            ],
        }
