from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeProvisioningFailureRule(FailureRule):
    """
    Detects Pending pods waiting for autoscaled capacity where node creation
    starts, but the new node never successfully joins as a usable Kubernetes
    Node.

    In managed clusters this often appears as:
    - kube-scheduler reports insufficient existing capacity
    - cluster-autoscaler triggers or observes node provisioning
    - cluster-autoscaler, node-controller, or cloud integration reports that
      the node failed to register, timed out during bootstrap, or stayed
      NotReady
    - the pod is still not Scheduled after that provisioning failure
    """

    name = "NodeProvisioningFailure"
    category = "Compound"
    severity = "High"
    priority = 80
    deterministic = True
    phases = ["Pending"]
    blocks = [
        "ClusterAutoscalerScaleUpFailed",
        "FailedScheduling",
        "InsufficientResources",
        "PendingUnschedulable",
        "RepeatedSchedulingBackoff",
        "NodeNotReady",
    ]
    requires = {
        "context": ["timeline"],
        "optional_objects": ["configmap", "node", "deployment", "replicaset"],
    }

    window_minutes = 45

    AUTOSCALER_COMPONENT_MARKERS = (
        "cluster-autoscaler",
        "cluster autoscaler",
        "autoscaler",
    )
    PROVISIONING_REASONS = {
        "TriggeredScaleUp",
        "ScaleUp",
        "ScaleUpStarted",
        "NodeProvisioning",
        "NodeProvisioningStarted",
    }
    PROVISIONING_MARKERS = (
        "triggered scale-up",
        "triggered scale up",
        "scale-up: group",
        "scale up: group",
        "increased node group",
        "increasing node group",
        "creating node",
        "creating instance",
        "creating vm",
        "provisioning node",
        "provisioning instance",
        "requested new node",
        "requested instance",
    )
    JOIN_FAILURE_REASONS = {
        "NodeProvisioningFailed",
        "NodeRegistrationFailed",
        "NodeNotReady",
        "FailedRegisterNode",
    }
    JOIN_FAILURE_REASONS_WITH_MARKERS = {
        "ScaleUpTimedOut",
        "ScaleUpFailed",
        "FailedScaleUp",
    }
    JOIN_FAILURE_MARKERS = (
        "failed to join",
        "failed to register",
        "node registration failed",
        "did not register",
        "didn't register",
        "not registered",
        "unregistered node",
        "unregistered nodes",
        "max node provision time",
        "node provision time exceeded",
        "timed out waiting for node",
        "timed out waiting for nodes",
        "timed out waiting for node registration",
        "timed out waiting for node to become ready",
        "node startup timed out",
        "node failed to become ready",
        "node did not become ready",
        "node didn't become ready",
        "node is not ready",
        "node stayed notready",
        "bootstrap failed",
        "kubelet bootstrap failed",
        "kubelet failed to register",
        "tls bootstrap",
        "csr",
        "cloud-init failed",
        "cloud init failed",
        "startup script failed",
    )
    EXCLUDED_SPECIFIC_MARKERS = (
        "quota",
        "quota_exceeded",
        "quotaexceeded",
        "resourceexhausted",
        "resource exhausted",
        "limit exceeded",
        "max node group size",
        "max size reached",
        "maximum size reached",
        "at max size",
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

    def _normalized(self, text: str) -> str:
        return " ".join(text.lower().replace("-", " ").split())

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

    def _has_any(self, text: str, markers: tuple[str, ...]) -> bool:
        normalized = self._normalized(text)
        compact = normalized.replace(" ", "")
        return any(marker in normalized or marker in compact for marker in markers)

    def _is_scheduler_capacity_failure(self, event: dict[str, Any]) -> bool:
        if event.get("reason") != "FailedScheduling":
            return False
        source = self._source_component(event)
        if source and "scheduler" not in source:
            return False
        return self._has_any(self._message(event), self.SCHEDULER_CAPACITY_MARKERS)

    def _from_autoscaler(self, event: dict[str, Any]) -> bool:
        source = self._source_component(event)
        message = self._message(event).lower()
        return any(
            marker in source or marker in message
            for marker in self.AUTOSCALER_COMPONENT_MARKERS
        )

    def _has_excluded_specific_root(self, text: str) -> bool:
        return self._has_any(text, self.EXCLUDED_SPECIFIC_MARKERS)

    def _is_provisioning_signal(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason") or "")
        message = self._message(event)
        if self._has_excluded_specific_root(message):
            return False
        if not self._from_autoscaler(event) and reason not in self.PROVISIONING_REASONS:
            return False
        return reason in self.PROVISIONING_REASONS or self._has_any(
            message, self.PROVISIONING_MARKERS
        )

    def _is_join_failure_signal(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason") or "")
        message = self._message(event)
        if self._has_excluded_specific_root(message):
            return False

        component = self._source_component(event)
        relevant_source = (
            self._from_autoscaler(event)
            or component in {"node-controller", "kubelet", "cloud-controller-manager"}
            or not component
        )
        if not relevant_source and reason not in self.JOIN_FAILURE_REASONS:
            return False

        if reason in self.JOIN_FAILURE_REASONS:
            return True
        if reason in self.JOIN_FAILURE_REASONS_WITH_MARKERS:
            return self._has_any(message, self.JOIN_FAILURE_MARKERS)

        return self._has_any(message, self.JOIN_FAILURE_MARKERS)

    def _status_configmap_join_failure(self, context: dict[str, Any]) -> str | None:
        configmaps = context.get("objects", {}).get("configmap", {})
        for name, configmap in configmaps.items():
            if name != "cluster-autoscaler-status":
                continue
            status_blob = str(configmap.get("data", {}).get("status") or "").strip()
            if not status_blob:
                continue
            if self._has_excluded_specific_root(status_blob):
                continue
            if self._has_any(status_blob, self.JOIN_FAILURE_MARKERS):
                return status_blob
        return None

    def _node_not_ready_join_failure(self, context: dict[str, Any]) -> str | None:
        for node_name, node in context.get("objects", {}).get("node", {}).items():
            labels = node.get("metadata", {}).get("labels", {})
            autoscaled = any(
                key in labels
                for key in (
                    "eks.amazonaws.com/nodegroup",
                    "cloud.google.com/gke-nodepool",
                    "agentpool",
                    "karpenter.sh/nodepool",
                )
            )
            for cond in node.get("status", {}).get("conditions", []):
                if cond.get("type") != "Ready" or cond.get("status") == "True":
                    continue
                text = f"{cond.get('reason', '')} {cond.get('message', '')}"
                if self._has_any(text, self.JOIN_FAILURE_MARKERS) or autoscaled:
                    return (
                        f"{node_name} Ready={cond.get('status')} "
                        f"reason={cond.get('reason', 'Unknown')}"
                    )
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

    def _recent_provisioning_signals(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_provisioning_signal(event)
        ]

    def _recent_join_failures(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_join_failure_signal(event)
        ]

    def _ordered_chain(
        self,
        scheduler_events: list[dict[str, Any]],
        provisioning_events: list[dict[str, Any]],
        join_failure_events: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        for scheduler_event in scheduler_events:
            scheduler_at = self._event_time(scheduler_event)
            for provisioning_event in provisioning_events:
                provisioning_at = self._event_time(provisioning_event)
                if (
                    scheduler_at is not None
                    and provisioning_at is not None
                    and provisioning_at < scheduler_at
                ):
                    continue
                for join_failure_event in join_failure_events:
                    join_failure_at = self._event_time(join_failure_event)
                    if (
                        provisioning_at is not None
                        and join_failure_at is not None
                        and join_failure_at < provisioning_at
                    ):
                        continue
                    return scheduler_event, provisioning_event, join_failure_event
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
        provisioning_events = self._recent_provisioning_signals(timeline)
        join_failure_events = self._recent_join_failures(timeline)
        status_signal = self._status_configmap_join_failure(context)
        node_signal = self._node_not_ready_join_failure(context)

        if not scheduler_events or not provisioning_events:
            return False

        chain = self._ordered_chain(
            scheduler_events, provisioning_events, join_failure_events
        )
        if not chain and not status_signal and not node_signal:
            return False

        after = (
            self._event_time(chain[2])
            if chain
            else self._event_time(provisioning_events[-1])
        )
        if self._scheduled_after(timeline, after):
            return False

        return True

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("NodeProvisioningFailure requires Timeline context")

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")

        scheduler_events = self._recent_capacity_failures(timeline)
        provisioning_events = self._recent_provisioning_signals(timeline)
        join_failure_events = self._recent_join_failures(timeline)
        chain_events = self._ordered_chain(
            scheduler_events, provisioning_events, join_failure_events
        )

        scheduler_event = (
            chain_events[0]
            if chain_events
            else (scheduler_events[0] if scheduler_events else {})
        )
        provisioning_event = (
            chain_events[1]
            if chain_events
            else (provisioning_events[0] if provisioning_events else {})
        )
        join_failure_event = (
            chain_events[2]
            if chain_events
            else (join_failure_events[0] if join_failure_events else {})
        )

        scheduler_message = self._message(scheduler_event)
        provisioning_reason = str(provisioning_event.get("reason") or "<unknown>")
        provisioning_message = self._message(provisioning_event)
        failure_reason = str(join_failure_event.get("reason") or "<unknown>")
        failure_message = self._message(join_failure_event)
        status_signal = self._status_configmap_join_failure(context)
        node_signal = self._node_not_ready_join_failure(context)
        duration_seconds = timeline.duration_between(
            lambda event: event.get("reason")
            in {
                "FailedScheduling",
                "TriggeredScaleUp",
                "ScaleUp",
                "NodeProvisioning",
                "NodeProvisioningFailed",
                "ScaleUpTimedOut",
                "NodeNotReady",
            }
        )

        causal_chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULER_REQUIRES_ADDITIONAL_CAPACITY",
                    message="Scheduler could not place the Pod on existing nodes because cluster capacity was insufficient",
                    role="scheduling_context",
                ),
                Cause(
                    code="NODE_PROVISIONING_STARTED",
                    message="Cluster autoscaler requested or started provisioning additional node capacity",
                    role="controller_context",
                ),
                Cause(
                    code="NEW_NODE_FAILED_TO_JOIN",
                    message="A newly provisioned node failed to register or become Ready in the cluster",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_PENDING",
                    message="Pod remains Pending because replacement node capacity never became schedulable",
                    role="workload_symptom",
                ),
            ]
        )

        controller_evidence = [
            f"{provisioning_reason}: {provisioning_message}",
        ]
        if failure_message:
            controller_evidence.append(f"{failure_reason}: {failure_message}")
        if status_signal:
            controller_evidence.append(status_signal)
        if node_signal:
            controller_evidence.append(node_signal)

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod is Pending after autoscaler provisioning started but new node capacity did not join",
                f"Scheduler message: {scheduler_message}",
            ],
            "controller:cluster-autoscaler": controller_evidence,
        }
        if status_signal:
            object_evidence["configmap:cluster-autoscaler-status"] = [status_signal]

        evidence = [
            f"Pod {namespace}/{pod_name} remains Pending",
            f"Scheduler reported insufficient capacity: {scheduler_message}",
            f"Cluster autoscaler started node provisioning: {provisioning_message}",
        ]
        if failure_message:
            evidence.append(f"Node provisioning failed to join: {failure_message}")
        if status_signal:
            evidence.append(
                "Cluster autoscaler status reports unregistered or NotReady nodes"
            )
        if node_signal:
            evidence.append(f"Provisioned node readiness signal: {node_signal}")
        evidence.append(
            "No successful Scheduled event observed after node provisioning failure"
        )
        if duration_seconds:
            evidence.append(
                f"Scheduler/provisioning failure window lasted {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "Newly provisioned nodes failed to join the cluster, leaving pods Pending",
            "confidence": 0.96,
            "blocking": True,
            "causes": causal_chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node bootstrap or kubelet registration failed before the node became Ready",
                "Cloud-init, startup scripts, or node image configuration prevented kubelet from joining the cluster",
                "Network, IAM, TLS bootstrap, or CSR approval problems blocked node registration",
                "Cluster autoscaler requested nodes, but the new capacity never became schedulable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl -n kube-system logs deployment/cluster-autoscaler",
                "kubectl -n kube-system get configmap cluster-autoscaler-status -o yaml",
                "kubectl get nodes -o wide",
                "Inspect cloud-init, kubelet, bootstrap, and node registration logs for the failed instance",
                "Check node IAM/identity, network reachability to the API server, and pending CSRs",
            ],
        }
