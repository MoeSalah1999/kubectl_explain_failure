from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class KubeletPodSyncFailureRule(FailureRule):
    """
    Detects kubelet SyncPod failures.

    Real-world behavior:

    kubelet continuously executes SyncPod() for every assigned pod.
    If SyncPod repeatedly fails, kubelet emits events such as:

      - Error syncing pod
      - SyncPod failed
      - failed to sync pod
      - pod sandbox changed repeatedly
      - kubelet unable to reconcile desired pod state

    These failures occur after scheduling and indicate kubelet runtime
    reconciliation failure rather than scheduler failure.

    Excludes:
      - image pull failures
      - PVC failures
      - DNS failures
      - CNI sandbox failures
      - container crash loops
    """

    name = "KubeletPodSyncFailure"
    category = "Node"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]

    container_states = [
        "waiting",
        "running",
        "terminated",
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
        "ContainerCreating",
    ]

    WINDOW_MINUTES = 20

    SYNC_FAILURE_MARKERS = (
        "error syncing pod",
        "failed syncing pod",
        "syncpod failed",
        "failed to sync pod",
        "error syncing",
        "sync pod failed",
        "failed to reconcile pod",
        "reconcile pod failed",
        "unable to sync pod",
        "pod sync failed",
    )

    KUBELET_COMPONENTS = ("kubelet",)

    EXCLUDED_MARKERS = (
        "imagepullbackoff",
        "errimagepull",
        "failed to pull image",
        "back-off pulling image",
        "failedcreatepodsandbox",
        "failed to create pod sandbox",
        "networkplugin",
        "cni",
        "ipam",
        "mountvolume",
        "failedmount",
        "unbound immediate persistentvolumeclaims",
        "crashloopbackoff",
        "oomkilled",
        "dns",
        "lookup ",
        "no such host",
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

    def _is_sync_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False

        message = self._message(event).lower()
        reason = self._reason(event).lower()
        component = self._source_component(event)

        if any(marker in message for marker in self.EXCLUDED_MARKERS):
            return False

        if any(marker in reason for marker in self.EXCLUDED_MARKERS):
            return False

        kubelet_signal = component in self.KUBELET_COMPONENTS or "kubelet" in message

        sync_signal = any(marker in message for marker in self.SYNC_FAILURE_MARKERS)

        return kubelet_signal and sync_signal

    def _recovered_after(
        self,
        timeline: Timeline,
        failure_time: datetime | None,
        pod: dict[str, Any],
    ) -> bool:
        for event in timeline.events:
            if not self._targets_current_pod(event, pod):
                continue

            if self._reason(event) not in self.RECOVERY_REASONS:
                continue

            event_time = self._event_time(event)

            if failure_time is None or event_time is None or event_time >= failure_time:
                return True

        return False

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        failures = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._is_sync_failure(e, pod)
        ]

        if not failures:
            return None

        latest = failures[-1]
        latest_time = self._event_time(latest)

        if self._recovered_after(
            timeline,
            latest_time,
            pod,
        ):
            return None

        return {
            "event": latest,
            "count": sum(self._occurrences(e) for e in failures),
            "duration_seconds": timeline.duration_between(
                lambda e: self._is_sync_failure(e, pod)
            ),
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(pod, timeline) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("KubeletPodSyncFailure requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
        )

        if candidate is None:
            raise ValueError("KubeletPodSyncFailure explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        node_name = pod.get("spec", {}).get("nodeName")

        message = self._message(candidate["event"])

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_ASSIGNED_TO_NODE",
                    message="Scheduler successfully assigned the pod to a node",
                    role="runtime_context",
                ),
                Cause(
                    code="KUBELET_SYNCPOD_FAILURE",
                    message="Kubelet repeatedly failed to reconcile desired pod state",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINERS_NOT_STARTED",
                    message="Pod startup could not complete because SyncPod operations failed",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} experienced kubelet SyncPod failures",
            f"Representative failure: {message}",
            f"Observed {candidate['count']} SyncPod failure occurrence(s)",
        ]

        if node_name:
            evidence.append(f"Pod is assigned to node {node_name}")

        if candidate["duration_seconds"]:
            evidence.append(
                f"Failures persisted for approximately "
                f"{candidate['duration_seconds'] / 60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [message],
        }

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Kubelet on this node repeatedly failed SyncPod reconciliation"
            ]

        return {
            "rule": self.name,
            "root_cause": "Kubelet failed to synchronize pod state",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet runtime reconciliation failed repeatedly",
                "Container runtime communication errors",
                "Internal kubelet state corruption or reconciliation failure",
                "Pod sandbox repeatedly recreated by kubelet",
                "Node resource or runtime instability preventing successful SyncPod execution",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                *([f"kubectl describe node {node_name}"] if node_name else []),
                "journalctl -u kubelet -n 500",
                "systemctl status kubelet",
                "crictl pods",
                "crictl ps -a",
                "Inspect kubelet logs for 'Error syncing pod' messages",
            ],
        }
