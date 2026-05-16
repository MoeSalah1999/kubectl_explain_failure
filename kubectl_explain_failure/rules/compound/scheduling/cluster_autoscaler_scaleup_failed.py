from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ClusterAutoscalerScaleUpFailedRule(FailureRule):
    """
    Detects Pending pods where scheduling requires more capacity, but
    cluster-autoscaler cannot add nodes.

    Real-world signals usually appear as:
    - kube-scheduler FailedScheduling events with insufficient capacity
    - cluster-autoscaler events such as ScaleUpFailed, FailedScaleUp,
      NotTriggerScaleUp, or NoScaleUp
    - no later Scheduled event for the pod

    This is intentionally stricter than plain InsufficientResources:
    the rule only matches when the autoscaler controller also reports that
    scale-up did not make progress.
    """

    name = "ClusterAutoscalerScaleUpFailed"
    category = "Compound"
    severity = "High"
    priority = 72
    deterministic = True
    phases = ["Pending"]
    blocks = [
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
    AUTOSCALER_FAILURE_REASONS = {
        "ScaleUpFailed",
        "FailedScaleUp",
        "FailedToScaleUp",
        "ScaleUpTimedOut",
        "NotTriggerScaleUp",
        "NoScaleUp",
    }
    AUTOSCALER_FAILURE_MARKERS = (
        "failed to increase",
        "failed to create",
        "failed to scale",
        "scale-up failed",
        "scale up failed",
        "scaleup failed",
        "max node group size reached",
        "max size reached",
        "quota",
        "limit exceeded",
        "no expansion options",
        "no node group",
        "no node groups",
        "no available node group",
        "backoff",
        "cloud provider",
        "managed instance group",
        "auto scaling group",
        "asg",
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

    def _is_autoscaler_failure(self, event: dict[str, Any]) -> bool:
        source = self._source_component(event)
        message = self._message(event).lower()
        reason = str(event.get("reason") or "")

        from_autoscaler = any(
            marker in source or marker in message
            for marker in self.AUTOSCALER_COMPONENT_MARKERS
        )
        if not from_autoscaler:
            return False

        if reason in {
            "ScaleUpFailed",
            "FailedScaleUp",
            "FailedToScaleUp",
            "ScaleUpTimedOut",
        }:
            return True

        if reason in self.AUTOSCALER_FAILURE_REASONS:
            return any(marker in message for marker in self.AUTOSCALER_FAILURE_MARKERS)

        return any(marker in message for marker in self.AUTOSCALER_FAILURE_MARKERS)

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

    def _recent_autoscaler_failures(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_autoscaler_failure(event)
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
        autoscaler_events = self._recent_autoscaler_failures(timeline)
        pair = self._ordered_failure_pair(scheduler_events, autoscaler_events)
        if not pair:
            return False

        _, autoscaler_event = pair
        if self._scheduled_after(timeline, self._event_time(autoscaler_event)):
            return False

        return True

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ClusterAutoscalerScaleUpFailed requires Timeline context")

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")

        scheduler_events = self._recent_capacity_failures(timeline)
        autoscaler_events = self._recent_autoscaler_failures(timeline)
        pair = self._ordered_failure_pair(scheduler_events, autoscaler_events)
        scheduler_event = (
            pair[0] if pair else (scheduler_events[0] if scheduler_events else {})
        )
        autoscaler_event = (
            pair[1] if pair else (autoscaler_events[0] if autoscaler_events else {})
        )

        scheduler_message = self._message(scheduler_event)
        autoscaler_message = self._message(autoscaler_event)
        autoscaler_reason = str(autoscaler_event.get("reason") or "<unknown>")
        duration_seconds = timeline.duration_between(
            lambda event: event.get("reason")
            in {
                "FailedScheduling",
                "ScaleUpFailed",
                "FailedScaleUp",
                "NotTriggerScaleUp",
                "NoScaleUp",
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
                    code="CLUSTER_AUTOSCALER_SCALE_UP_FAILED",
                    message="Cluster autoscaler did not add nodes for the Pending Pod",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_PENDING",
                    message="Pod remains Pending because the required replacement capacity was not provisioned",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod is Pending after scheduler capacity rejection and autoscaler scale-up failure",
                f"Scheduler message: {scheduler_message}",
            ],
            "controller:cluster-autoscaler": [
                f"{autoscaler_reason}: {autoscaler_message}",
            ],
        }

        for name, configmap in context.get("objects", {}).get("configmap", {}).items():
            if name != "cluster-autoscaler-status":
                continue
            status_blob = str(configmap.get("data", {}).get("status") or "").strip()
            if status_blob:
                object_evidence[f"configmap:{name}"] = [status_blob]

        evidence = [
            f"Pod {namespace}/{pod_name} remains Pending",
            f"Scheduler reported insufficient capacity: {scheduler_message}",
            f"Cluster autoscaler reported {autoscaler_reason}: {autoscaler_message}",
            "No successful Scheduled event observed after autoscaler failure",
        ]
        if duration_seconds:
            evidence.append(
                f"Scheduler/autoscaler failure window lasted {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "Cluster autoscaler failed to add nodes for a Pending pod",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node group or cloud provider quota prevents scale-up",
                "Cluster autoscaler reached the node group maximum size",
                "No scalable node group can fit the pod's requested CPU, memory, pods, or ephemeral storage",
                "Cloud provider node provisioning is failing or in backoff",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl -n kube-system logs deployment/cluster-autoscaler",
                "kubectl -n kube-system get configmap cluster-autoscaler-status -o yaml",
                "Check node group max size, cloud quota, and autoscaler backoff events",
            ],
        }
