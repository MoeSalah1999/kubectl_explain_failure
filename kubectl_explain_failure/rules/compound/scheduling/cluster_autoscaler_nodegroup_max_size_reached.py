from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ClusterAutoscalerNodeGroupMaxSizeReachedRule(FailureRule):
    """
    Detects Pending pods that need additional capacity, but the relevant
    autoscaled node group has already reached its configured maximum size.

    This models a common managed Kubernetes failure mode: kube-scheduler
    rejects the pod for capacity, cluster-autoscaler evaluates the pending
    pod, then reports that scale-up is blocked because a node pool/node group
    is already at max size.
    """

    name = "ClusterAutoscalerNodeGroupMaxSizeReached"
    category = "Compound"
    severity = "High"
    priority = 82
    deterministic = True
    phases = ["Pending"]
    blocks = [
        "ClusterAutoscalerScaleUpFailed",
        "FailedScheduling",
        "InsufficientResources",
        "PendingUnschedulable",
        "RepeatedSchedulingBackoff",
    ]
    requires = {
        "context": ["timeline"],
        "optional_objects": ["configmap", "node", "deployment", "replicaset"],
    }

    window_minutes = 30

    AUTOSCALER_COMPONENT_MARKERS = (
        "cluster-autoscaler",
        "cluster autoscaler",
        "autoscaler",
    )
    AUTOSCALER_REASONS = {
        "NotTriggerScaleUp",
        "NoScaleUp",
        "ScaleUpFailed",
        "FailedScaleUp",
        "FailedToScaleUp",
    }
    MAX_SIZE_MARKERS = (
        "max node group size reached",
        "maximum node group size reached",
        "node group max size reached",
        "max node group size",
        "maximum size reached",
        "max size reached",
        "reached max size",
        "reached maximum size",
        "at max size",
        "at maximum size",
        "maxsize",
        "max size",
    )
    SCHEDULER_CAPACITY_MARKERS = (
        "insufficient cpu",
        "insufficient memory",
        "insufficient ephemeral-storage",
        "insufficient ephemeral storage",
        "insufficient pods",
        "too many pods",
        "didn't have enough resource",
        "did not have enough resource",
    )

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

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

    def _is_scheduler_capacity_failure(self, event: dict[str, Any]) -> bool:
        if event.get("reason") != "FailedScheduling":
            return False
        source = self._source_component(event)
        if source and "scheduler" not in source:
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.SCHEDULER_CAPACITY_MARKERS)

    def _is_autoscaler_max_size_signal(self, event: dict[str, Any]) -> bool:
        source = self._source_component(event)
        message = self._message(event).lower()
        reason = str(event.get("reason") or "")

        from_autoscaler = any(
            marker in source or marker in message
            for marker in self.AUTOSCALER_COMPONENT_MARKERS
        )
        if not from_autoscaler and reason not in self.AUTOSCALER_REASONS:
            return False

        if not any(marker in message for marker in self.MAX_SIZE_MARKERS):
            return False

        return reason in self.AUTOSCALER_REASONS or from_autoscaler

    def _status_configmap_max_size_signal(self, context: dict[str, Any]) -> str | None:
        configmaps = context.get("objects", {}).get("configmap", {})
        for name, configmap in configmaps.items():
            if name != "cluster-autoscaler-status":
                continue
            status_blob = str(configmap.get("data", {}).get("status") or "").strip()
            normalized = status_blob.lower()
            if status_blob and any(
                marker in normalized for marker in self.MAX_SIZE_MARKERS
            ):
                return status_blob
        return None

    def _scheduled_after(self, timeline: Timeline, after: datetime | None) -> bool:
        for event in timeline.events:
            if event.get("reason") != "Scheduled":
                continue
            scheduled_at = self._event_time(event)
            if after is None or scheduled_at is None or scheduled_at >= after:
                return True
        return False

    def _recent_capacity_failures(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(
                self.window_minutes, reason="FailedScheduling"
            )
            if self._is_scheduler_capacity_failure(event)
        ]

    def _recent_max_size_signals(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_autoscaler_max_size_signal(event)
        ]

    def _ordered_failure_pair(
        self,
        scheduler_events: list[dict[str, Any]],
        autoscaler_events: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        for scheduler_event in scheduler_events:
            scheduler_at = self._event_time(scheduler_event)
            for autoscaler_event in autoscaler_events:
                autoscaler_at = self._event_time(autoscaler_event)
                if scheduler_at is None or autoscaler_at is None:
                    return scheduler_event, autoscaler_event
                if autoscaler_at >= scheduler_at:
                    return scheduler_event, autoscaler_event
        return None

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        if context.get("blocking_pvc") is not None:
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        scheduler_events = self._recent_capacity_failures(timeline)
        if not scheduler_events:
            return False

        max_size_events = self._recent_max_size_signals(timeline)
        pair = self._ordered_failure_pair(scheduler_events, max_size_events)
        status_signal = self._status_configmap_max_size_signal(context)
        if not pair and not status_signal:
            return False

        after = (
            self._event_time(pair[1])
            if pair
            else self._event_time(scheduler_events[-1])
        )
        if self._scheduled_after(timeline, after):
            return False

        return True

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError(
                "ClusterAutoscalerNodeGroupMaxSizeReached requires Timeline context"
            )

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")

        scheduler_events = self._recent_capacity_failures(timeline)
        max_size_events = self._recent_max_size_signals(timeline)
        pair = self._ordered_failure_pair(scheduler_events, max_size_events)
        scheduler_event = (
            pair[0] if pair else (scheduler_events[0] if scheduler_events else {})
        )
        autoscaler_event = (
            pair[1] if pair else (max_size_events[0] if max_size_events else {})
        )

        scheduler_message = self._message(scheduler_event)
        autoscaler_message = self._message(autoscaler_event)
        autoscaler_reason = str(autoscaler_event.get("reason") or "<unknown>")
        status_signal = self._status_configmap_max_size_signal(context)
        duration_seconds = timeline.duration_between(
            lambda event: event.get("reason")
            in {
                "FailedScheduling",
                "NotTriggerScaleUp",
                "NoScaleUp",
                "ScaleUpFailed",
                "FailedScaleUp",
            }
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_REQUIRES_ADDITIONAL_CAPACITY",
                    message="Scheduler could not place the Pod on existing nodes because cluster capacity was insufficient",
                    role="scheduling_context",
                ),
                Cause(
                    code="NODE_GROUP_MAX_SIZE_REACHED",
                    message="Cluster autoscaler could not add nodes because the matching node group is already at its configured maximum size",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_PENDING",
                    message="Pod remains Pending until the node group limit is raised or capacity is freed",
                    role="workload_symptom",
                ),
            ]
        )

        controller_evidence = []
        if autoscaler_message:
            controller_evidence.append(f"{autoscaler_reason}: {autoscaler_message}")
        if status_signal:
            controller_evidence.append(status_signal)

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod is Pending after scheduler capacity rejection and node group max-size signal",
                f"Scheduler message: {scheduler_message}",
            ],
            "controller:cluster-autoscaler": controller_evidence,
        }

        if status_signal:
            object_evidence["configmap:cluster-autoscaler-status"] = [status_signal]

        evidence = [
            f"Pod {namespace}/{pod_name} remains Pending",
            f"Scheduler reported insufficient capacity: {scheduler_message}",
        ]
        if autoscaler_message:
            evidence.append(
                f"Cluster autoscaler reported {autoscaler_reason}: {autoscaler_message}"
            )
        if status_signal:
            evidence.append(
                "Cluster autoscaler status reports the node group is at max size"
            )
        evidence.append(
            "No successful Scheduled event observed after node group max-size signal"
        )
        if duration_seconds:
            evidence.append(
                f"Scheduler/autoscaler max-size window lasted {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "Cluster autoscaler cannot add nodes because the node group reached max size",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Managed node pool or autoscaling group maximum size is too low for current demand",
                "Cluster autoscaler found a fitting node group but it is already at its max node count",
                "Workload resource requests require more nodes than the node group is allowed to create",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl -n kube-system logs deployment/cluster-autoscaler",
                "kubectl -n kube-system get configmap cluster-autoscaler-status -o yaml",
                "Inspect the managed node pool or autoscaling group min/max/current size",
                "Raise the node group max size or add another autoscaled node group that can fit the pod",
            ],
        }
