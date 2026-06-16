from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CSIVolumeLimitExceededRule(FailureRule):
    """
    Detects Pods that cannot be scheduled or attached because the target node
    has reached the CSI driver's attachable volume limit.

    Real-world behavior:
    - Common on EBS, PD, Azure Disk, vSphere, and other CSI-backed block volumes.
    - Scheduler emits:
        "node(s) had volume node affinity conflict"
        "max volume count exceeded"
        "node(s) exceed max volume count"
        "node(s) had insufficient attachable volumes"
    - AttachDetach controller emits:
        "AttachVolume.Attach failed"
        "exceeded max volume limit"
        "too many attached volumes"
    - Pod typically remains Pending or repeatedly fails volume attachment.
    - Node may otherwise be healthy and Ready.

    Exclusions:
    - Missing PVCs
    - Unbound PVCs
    - StorageClass provisioning failures
    - CSI driver outages
    - Volume mount failures inside kubelet after successful attachment
    """

    name = "CSIVolumeLimitExceeded"
    category = "Storage"
    severity = "High"
    priority = 91
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "csinode",
            "pod",
            "persistentvolumeclaim",
            "persistentvolume",
        ],
    }

    blocks = [
        "FailedAttachVolume",
        "VolumeMountFailure",
        "PodUnschedulable",
    ]

    WINDOW_MINUTES = 30

    LIMIT_MARKERS = (
        "max volume count",
        "exceed max volume count",
        "exceeded max volume count",
        "exceeded max volume limit",
        "too many attached volumes",
        "volume limit exceeded",
        "attachable volumes limit",
        "insufficient attachable volumes",
        "node(s) exceed max volume count",
        "node(s) had insufficient attachable volumes",
        "maximum number of volumes",
        "max number of volumes",
        "volume attachments limit",
        "cannot attach volume",
        "attachment limit reached",
    )

    ATTACH_REASONS = {
        "FailedAttachVolume",
        "FailedScheduling",
        "AttachVolume",
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

    def _recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return timeline.events_within_window(self.WINDOW_MINUTES)

    def _is_volume_limit_event(self, event: dict[str, Any]) -> bool:
        reason = self._reason(event)
        message = self._message(event).lower()

        if reason in self.ATTACH_REASONS:
            if any(marker in message for marker in self.LIMIT_MARKERS):
                return True

        return any(marker in message for marker in self.LIMIT_MARKERS)

    def _node_name(
        self,
        pod: dict[str, Any],
        candidate_events: list[dict[str, Any]],
    ) -> str | None:
        node_name = pod.get("spec", {}).get("nodeName")
        if node_name:
            return str(node_name)

        for event in candidate_events:
            msg = self._message(event)

            # Common scheduler wording:
            # "0/10 nodes are available: 1 node(s) exceed max volume count."
            if " node " in msg.lower():
                return None

            involved = event.get("involvedObject", {})
            if isinstance(involved, dict):
                node = involved.get("nodeName")
                if node:
                    return str(node)

        return None

    def _csinode_signal(
        self,
        context: dict[str, Any],
        node_name: str | None,
    ) -> str | None:
        if not node_name:
            return None

        csinodes = context.get("objects", {}).get("csinode", {})

        node_obj = csinodes.get(node_name)
        if not isinstance(node_obj, dict):
            return None

        drivers = node_obj.get("spec", {}).get("drivers", []) or []

        for driver in drivers:
            allocatable = (
                driver.get("allocatable", {}) if isinstance(driver, dict) else {}
            )

            count = allocatable.get("count")
            name = driver.get("name")

            if count is not None:
                return (
                    f"CSINode reports attachable volume limit "
                    f"count={count} for CSI driver {name}"
                )

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        recent = self._recent_events(timeline)

        limit_events = [e for e in recent if self._is_volume_limit_event(e)]

        if not limit_events:
            return None

        node_name = self._node_name(pod, limit_events)

        occurrences = sum(self._occurrences(e) for e in limit_events)

        duration = timeline.duration_between(lambda e: self._is_volume_limit_event(e))

        csinode_signal = self._csinode_signal(context, node_name)

        object_evidence: dict[str, list[str]] = {}

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Node reached CSI attachable volume limit"
            ]

        if csinode_signal and node_name:
            object_evidence.setdefault(
                f"csinode:{node_name}",
                [],
            ).append(csinode_signal)

        return {
            "event": limit_events[-1],
            "occurrences": occurrences,
            "duration": duration,
            "node_name": node_name,
            "csinode_signal": csinode_signal,
            "object_evidence": object_evidence,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("CSIVolumeLimitExceeded requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("CSIVolumeLimitExceeded explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = candidate["node_name"]

        message = self._message(candidate["event"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_ATTACH_LIMIT_ENFORCED",
                    message=(
                        "The CSI driver enforces a maximum number of "
                        "attachable volumes per node"
                    ),
                    role="infrastructure_constraint",
                ),
                Cause(
                    code="NODE_VOLUME_LIMIT_REACHED",
                    message=(
                        "The selected node has reached its attachable "
                        "volume capacity"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CANNOT_ATTACH_STORAGE",
                    message=("Required volumes cannot be attached to the node"),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} encountered CSI volume attachment limit enforcement",
            f"Representative scheduler/attach event: {message}",
            (
                f"Observed {candidate['occurrences']} volume-limit "
                f"occurrence(s) within the last {self.WINDOW_MINUTES} minutes"
            ),
        ]

        if node_name:
            evidence.append(f"Failure is associated with node {node_name}")

        if candidate["csinode_signal"]:
            evidence.append(candidate["csinode_signal"])

        if candidate["duration"]:
            evidence.append(
                f"Volume limit signals persisted for "
                f"{candidate['duration'] / 60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [message],
            **candidate["object_evidence"],
        }

        confidence = 0.98
        if not node_name:
            confidence = 0.95

        return {
            "rule": self.name,
            "root_cause": (
                "CSI attachable volume limit has been exceeded on the target node"
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
                "The node already has the maximum number of CSI-attached volumes allowed by the cloud provider or storage platform",
                "A high-density workload scheduled too many PVC-backed Pods onto the same node",
                "The CSI driver's attach limit is lower than workload storage demand",
                "Volume attachments from completed or terminating workloads are still consuming attach slots",
                "Cluster autoscaling or scheduling constraints concentrated stateful workloads onto a small number of nodes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get volumeattachments",
                *([f"kubectl describe node {node_name}"] if node_name else []),
                "kubectl get csinode -o yaml",
                "Review CSI driver attach limits and current volume attachment counts",
                "Reschedule workloads or add nodes to distribute attached volumes",
            ],
        }
