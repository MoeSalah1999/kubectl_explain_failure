from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ClusterAutoscalerInsufficientCloudQuotaRule(FailureRule):
    """
    Detects Pending pods where cluster-autoscaler cannot create nodes because
    the cloud provider rejects node creation for quota exhaustion.

    Real-world examples include AWS vCPU or instance limits, GCP regional CPU
    or address quota exhaustion, and Azure VM family cores or public IP quota
    limits. The rule requires both scheduler capacity pressure and a
    cloud-quota signal from cluster-autoscaler, ordered in the event timeline.
    """

    name = "ClusterAutoscalerInsufficientCloudQuota"
    category = "Compound"
    severity = "High"
    priority = 84
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
        "ScaleUpTimedOut",
    }
    QUOTA_MARKERS = (
        "quota exceeded",
        "quotaexceeded",
        "quota_exceeded",
        "quota is exhausted",
        "quota exhausted",
        "insufficient quota",
        "not enough quota",
        "resourceexhausted",
        "resource exhausted",
        "limit exceeded",
        "limitexceeded",
        "vcpulimitexceeded",
        "vcpu limit exceeded",
        "instance limit exceeded",
        "instancelimitexceeded",
        "regional cpu quota",
        "regional cpus quota",
        "cpu quota",
        "cpus_all_regions",
        "cores quota",
        "standard cores",
        "vm family cores",
        "operationnotallowed",
        "operation not allowed",
        "in_use_addresses",
        "in-use addresses",
        "address quota",
        "public ip address quota",
        "public ip quota",
        "ssd_total_gb",
        "disk quota",
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

    def _has_quota_signal(self, text: str) -> bool:
        normalized = " ".join(text.lower().replace("-", " ").split())
        compact = normalized.replace(" ", "")
        return any(
            marker in normalized or marker in compact for marker in self.QUOTA_MARKERS
        )

    def _is_scheduler_capacity_failure(self, event: dict[str, Any]) -> bool:
        if event.get("reason") != "FailedScheduling":
            return False
        source = self._source_component(event)
        if source and "scheduler" not in source:
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.SCHEDULER_CAPACITY_MARKERS)

    def _is_autoscaler_quota_signal(self, event: dict[str, Any]) -> bool:
        source = self._source_component(event)
        message = self._message(event)
        reason = str(event.get("reason") or "")

        from_autoscaler = any(
            marker in source or marker in message.lower()
            for marker in self.AUTOSCALER_COMPONENT_MARKERS
        )
        if not from_autoscaler and reason not in self.AUTOSCALER_REASONS:
            return False

        if not self._has_quota_signal(message):
            return False

        return reason in self.AUTOSCALER_REASONS or from_autoscaler

    def _status_configmap_quota_signal(self, context: dict[str, Any]) -> str | None:
        configmaps = context.get("objects", {}).get("configmap", {})
        for name, configmap in configmaps.items():
            if name != "cluster-autoscaler-status":
                continue
            status_blob = str(configmap.get("data", {}).get("status") or "").strip()
            if status_blob and self._has_quota_signal(status_blob):
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

    def _recent_quota_signals(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_autoscaler_quota_signal(event)
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

        quota_events = self._recent_quota_signals(timeline)
        pair = self._ordered_failure_pair(scheduler_events, quota_events)
        status_signal = self._status_configmap_quota_signal(context)
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
                "ClusterAutoscalerInsufficientCloudQuota requires Timeline context"
            )

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")

        scheduler_events = self._recent_capacity_failures(timeline)
        quota_events = self._recent_quota_signals(timeline)
        pair = self._ordered_failure_pair(scheduler_events, quota_events)
        scheduler_event = (
            pair[0] if pair else (scheduler_events[0] if scheduler_events else {})
        )
        quota_event = pair[1] if pair else (quota_events[0] if quota_events else {})

        scheduler_message = self._message(scheduler_event)
        quota_message = self._message(quota_event)
        quota_reason = str(quota_event.get("reason") or "<unknown>")
        status_signal = self._status_configmap_quota_signal(context)
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
                    code="CLOUD_QUOTA_EXHAUSTED",
                    message="Cluster autoscaler could not create replacement nodes because cloud provider quota was exhausted",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_PENDING",
                    message="Pod remains Pending until cloud quota is increased, released, or capacity is added elsewhere",
                    role="workload_symptom",
                ),
            ]
        )

        controller_evidence = []
        if quota_message:
            controller_evidence.append(f"{quota_reason}: {quota_message}")
        if status_signal:
            controller_evidence.append(status_signal)

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod is Pending after scheduler capacity rejection and cloud quota exhaustion",
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
        if quota_message:
            evidence.append(
                f"Cluster autoscaler reported {quota_reason}: {quota_message}"
            )
        if status_signal:
            evidence.append("Cluster autoscaler status reports cloud quota exhaustion")
        evidence.append("No successful Scheduled event observed after quota failure")
        if duration_seconds:
            evidence.append(
                f"Scheduler/autoscaler quota failure window lasted {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "Cluster autoscaler cannot add nodes because cloud provider quota is exhausted",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "AWS vCPU, instance, ENI, or address limits prevent node creation",
                "GCP regional CPU, address, disk, or project quota prevents node creation",
                "Azure VM family cores, public IP, or regional quota prevents node creation",
                "Cluster autoscaler found a fitting node group but the cloud provider rejected scale-up for quota reasons",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl -n kube-system logs deployment/cluster-autoscaler",
                "kubectl -n kube-system get configmap cluster-autoscaler-status -o yaml",
                "Check cloud provider quota dashboards for regional CPU, VM, IP, disk, or instance limits",
                "Request a quota increase or scale a node group in a region/zone with available quota",
            ],
        }
