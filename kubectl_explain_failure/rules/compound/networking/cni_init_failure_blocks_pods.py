from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class SequenceInfo(TypedDict):
    precursor_event: dict[str, Any]
    symptom_event: dict[str, Any]
    strength: int


class CandidateInfo(TypedDict):
    cni_pod_name: str
    cni_namespace: str
    node_name: str
    init_container_name: str
    init_restart_count: int
    init_state_name: str
    sequence_count: int
    total_strength: int
    precursor_message: str
    symptom_message: str


class CNIInitFailureBlocksPodsRule(FailureRule):
    """
    Detects node-local CNI daemon/init bootstrap failures that later block
    ordinary workload pods from creating a sandbox on the same node.

    Real-world interpretation:
    - a node-local CNI DaemonSet pod exists on the assigned node
    - that CNI pod has a failing init/bootstrap container such as install-cni
    - kubelet later emits CNI/network setup failures for a workload pod on
      the same node because the node-local CNI bootstrap never completed

    Exclusions:
    - generic CNI failures with no evidence of a failing node-local CNI pod
    - CNI IP exhaustion
    - node route / NetworkUnavailable cascades
    - container-runtime outages unrelated to CNI bootstrap
    """

    name = "CNIInitFailureBlocksPods"
    category = "Compound"
    priority = 66
    deterministic = True

    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pod"],
    }

    blocks = [
        "CNIConfigMissing",
        "CNIPluginFailure",
    ]

    WINDOW_MINUTES = 30
    MAX_PRECURSOR_TO_SYMPTOM_GAP = timedelta(minutes=10)
    MIN_EFFECTIVE_OCCURRENCES = 2

    CNI_POD_MARKERS = (
        "aws-node",
        "aws-cni",
        "calico-node",
        "cilium",
        "flannel",
        "weave-net",
        "canal",
        "multus",
        "antrea-agent",
        "kube-router",
        "kindnet",
        "cni",
    )

    INIT_FAILURE_REASONS = {
        "backoff",
        "failed",
        "unhealthy",
    }

    INIT_FAILURE_WAITING_REASONS = {
        "CrashLoopBackOff",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "ContainerCannotRun",
        "ErrImagePull",
        "ImagePullBackOff",
    }

    INIT_MESSAGE_MARKERS = (
        "install-cni",
        "cni",
        "/etc/cni/net.d",
        ".conflist",
        ".conf",
        "plugin binary",
        "plugin not initialized",
        "failed to write",
        "failed to copy",
        "permission denied",
    )

    WORKLOAD_SYMPTOM_REASONS = {
        "failedcreatepodsandbox",
        "cnipluginfailure",
    }

    WORKLOAD_MARKERS = (
        "cni",
        "network plugin",
        "pod sandbox",
        "setup network for sandbox",
        "set up pod network",
        "failed to create pod sandbox",
        "failed to setup network",
        "failed to load cni config",
        "no networks found in /etc/cni/net.d",
        "no valid networks found in /etc/cni/net.d",
        "cni config uninitialized",
    )

    RUNTIME_EXCLUSION_MARKERS = (
        "container runtime is down",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "runtime.v1.runtimeservice",
        "unsupported runtime api version",
        "runtime api version is not supported",
        "containerd.sock",
        "cri-o.sock",
        "connection refused",
    )

    IP_EXHAUSTION_EXCLUSION_MARKERS = (
        "no available ip",
        "no more ips",
        "address pool is exhausted",
        "ip pool exhausted",
        "failed to assign an ip address",
        "ipam",
    )

    NETWORK_UNAVAILABLE_EXCLUSION_MARKERS = (
        "nodenetworkunavailable",
        "networkunavailable",
        "routecontroller failed to create a route",
        "failed to create a route to the node",
        "failed to allocate cidr",
        "podcidr",
        "cidr conflict",
        "overlaps with node",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_start(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_start(item[1]) is None else 0,
                    self._event_start(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _targets_pod(
        self,
        event: dict[str, Any],
        pod_name: str,
        namespace: str,
    ) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return False
        kind = str(involved.get("kind", "")).lower()
        if kind and kind != "pod":
            return False
        if involved.get("name") and involved.get("name") != pod_name:
            return False
        if involved.get("namespace") and involved.get("namespace") != namespace:
            return False
        return True

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
    ) -> bool:
        lowered = container_name.lower()
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path:
                return lowered in field_path

        message = self._event_message(event)
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"containers{{{lowered}}}",
            f"failed container {lowered}",
        )
        return any(pattern in message for pattern in patterns)

    def _pod_identity_text(self, pod_obj: dict[str, Any]) -> str:
        metadata = pod_obj.get("metadata", {})
        labels = metadata.get("labels", {}) or {}
        annotations = metadata.get("annotations", {}) or {}
        spec = pod_obj.get("spec", {})
        statuses = pod_obj.get("status", {})

        values = [
            metadata.get("name", ""),
            metadata.get("namespace", ""),
            *labels.keys(),
            *labels.values(),
            *annotations.keys(),
            *annotations.values(),
            *[
                container.get("name", "")
                for container in spec.get("containers", []) or []
                if isinstance(container, dict)
            ],
            *[
                container.get("name", "")
                for container in spec.get("initContainers", []) or []
                if isinstance(container, dict)
            ],
            *[
                status.get("name", "")
                for status in statuses.get("containerStatuses", []) or []
                if isinstance(status, dict)
            ],
            *[
                status.get("name", "")
                for status in statuses.get("initContainerStatuses", []) or []
                if isinstance(status, dict)
            ],
        ]
        return " ".join(str(value).lower() for value in values if value)

    def _is_cni_node_pod(self, pod_obj: dict[str, Any]) -> bool:
        metadata = pod_obj.get("metadata", {})
        if metadata.get("namespace") != "kube-system":
            return False
        text = self._pod_identity_text(pod_obj)
        return any(marker in text for marker in self.CNI_POD_MARKERS)

    def _is_target_workload_pod(self, pod: dict[str, Any]) -> bool:
        return not self._is_cni_node_pod(pod)

    def _failing_init_statuses(self, cni_pod: dict[str, Any]) -> list[dict[str, Any]]:
        failures: list[dict[str, Any]] = []
        for status in cni_pod.get("status", {}).get("initContainerStatuses", []) or []:
            if not isinstance(status, dict):
                continue
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            terminated = state.get("terminated", {}) or {}
            last_terminated = (status.get("lastState", {}) or {}).get(
                "terminated", {}
            ) or {}
            if waiting.get("reason") in self.INIT_FAILURE_WAITING_REASONS:
                failures.append(status)
                continue
            if terminated and int(terminated.get("exitCode", 0) or 0) != 0:
                failures.append(status)
                continue
            if (
                last_terminated
                and int(last_terminated.get("exitCode", 0) or 0) != 0
                and int(status.get("restartCount", 0) or 0) > 0
            ):
                failures.append(status)
        return failures

    def _init_state_name(self, status: dict[str, Any]) -> str:
        state = status.get("state", {}) or {}
        if "waiting" in state:
            return "waiting"
        if "terminated" in state:
            return "terminated"
        if "running" in state:
            return "running"
        return "unknown"

    def _is_init_failure_event(
        self,
        event: dict[str, Any],
        *,
        cni_pod_name: str,
        namespace: str,
        init_container_name: str,
    ) -> bool:
        if self._event_component(event) not in {"", "kubelet"}:
            return False
        if self._event_reason(event) not in self.INIT_FAILURE_REASONS:
            return False
        if not self._targets_pod(event, cni_pod_name, namespace):
            return False
        if not self._container_event_match(event, init_container_name):
            return False
        message = self._event_message(event)
        return any(marker in message for marker in self.INIT_MESSAGE_MARKERS)

    def _has_workload_exclusion(self, event: dict[str, Any]) -> bool:
        text = f"{self._event_reason(event)} {self._event_message(event)}"
        return (
            any(marker in text for marker in self.RUNTIME_EXCLUSION_MARKERS)
            or any(marker in text for marker in self.IP_EXHAUSTION_EXCLUSION_MARKERS)
            or any(
                marker in text for marker in self.NETWORK_UNAVAILABLE_EXCLUSION_MARKERS
            )
        )

    def _is_workload_cni_symptom(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        namespace: str,
    ) -> bool:
        if self._has_workload_exclusion(event):
            return False
        if not self._targets_pod(event, pod_name, namespace):
            return False
        if self._event_reason(event) not in self.WORKLOAD_SYMPTOM_REASONS:
            return False
        message = self._event_message(event)
        return any(marker in message for marker in self.WORKLOAD_MARKERS)

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> CandidateInfo | None:
        if not self._is_target_workload_pod(pod):
            return None

        node_name = str(pod.get("spec", {}).get("nodeName", "") or "")
        pod_name = str(pod.get("metadata", {}).get("name", "") or "")
        namespace = str(
            pod.get("metadata", {}).get("namespace", "default") or "default"
        )
        if not node_name or not pod_name:
            return None

        ordered = self._ordered_recent_events(timeline)
        workload_events = [
            event
            for event in ordered
            if self._is_workload_cni_symptom(
                event,
                pod_name=pod_name,
                namespace=namespace,
            )
        ]
        if not workload_events:
            return None

        pod_objects = context.get("objects", {}).get("pod", {})
        best: CandidateInfo | None = None

        for pod_key, cni_pod in pod_objects.items():
            if not isinstance(cni_pod, dict) or not self._is_cni_node_pod(cni_pod):
                continue
            if str(cni_pod.get("spec", {}).get("nodeName", "") or "") != node_name:
                continue

            cni_name = str(cni_pod.get("metadata", {}).get("name", "") or "")
            cni_namespace = str(
                cni_pod.get("metadata", {}).get("namespace", "kube-system")
                or "kube-system"
            )
            if not cni_name or pod_key == pod_name:
                continue

            for init_status in self._failing_init_statuses(cni_pod):
                init_name = str(init_status.get("name", "") or "")
                if not init_name:
                    continue

                precursor_events = [
                    event
                    for event in ordered
                    if self._is_init_failure_event(
                        event,
                        cni_pod_name=cni_name,
                        namespace=cni_namespace,
                        init_container_name=init_name,
                    )
                ]
                if not precursor_events:
                    continue

                sequences: list[SequenceInfo] = []
                symptom_index = 0
                for precursor in precursor_events:
                    precursor_start = self._event_start(precursor)
                    precursor_end = self._event_end(precursor) or precursor_start
                    if precursor_start is None or precursor_end is None:
                        continue

                    for idx in range(symptom_index, len(workload_events)):
                        symptom = workload_events[idx]
                        symptom_start = self._event_start(symptom)
                        if symptom_start is None or symptom_start < precursor_start:
                            continue
                        if (
                            symptom_start - precursor_end
                            > self.MAX_PRECURSOR_TO_SYMPTOM_GAP
                        ):
                            break
                        sequences.append(
                            {
                                "precursor_event": precursor,
                                "symptom_event": symptom,
                                "strength": min(
                                    self._occurrences(precursor),
                                    self._occurrences(symptom),
                                ),
                            }
                        )
                        symptom_index = idx + 1
                        break

                if not sequences:
                    continue

                total_strength = sum(seq["strength"] for seq in sequences)
                if (
                    len(sequences) < 2
                    and total_strength < self.MIN_EFFECTIVE_OCCURRENCES
                ):
                    continue

                dominant = max(
                    sequences,
                    key=lambda seq: (
                        seq["strength"],
                        self._occurrences(seq["symptom_event"]),
                    ),
                )
                candidate: CandidateInfo = {
                    "cni_pod_name": cni_name,
                    "cni_namespace": cni_namespace,
                    "node_name": node_name,
                    "init_container_name": init_name,
                    "init_restart_count": int(init_status.get("restartCount", 0) or 0),
                    "init_state_name": self._init_state_name(init_status),
                    "sequence_count": len(sequences),
                    "total_strength": total_strength,
                    "precursor_message": str(
                        dominant["precursor_event"].get("message", "")
                    ).strip(),
                    "symptom_message": str(
                        dominant["symptom_event"].get("message", "")
                    ).strip(),
                }
                if best is None or (
                    candidate["total_strength"],
                    candidate["sequence_count"],
                    candidate["init_restart_count"],
                ) > (
                    best["total_strength"],
                    best["sequence_count"],
                    best["init_restart_count"],
                ):
                    best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CNIInitFailureBlocksPods requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("CNIInitFailureBlocksPods explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        cni_pod_name = candidate["cni_pod_name"]
        node_name = candidate["node_name"]
        init_name = candidate["init_container_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_LOCAL_CNI_AGENT_PRESENT",
                    message=f"Assigned node '{node_name}' relies on node-local CNI pod '{cni_pod_name}' to bootstrap pod networking",
                    role="infrastructure_context",
                ),
                Cause(
                    code="CNI_INIT_BOOTSTRAP_FAILED",
                    message=f"CNI init container '{init_name}' failed before node-local network bootstrap completed",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_POD_NETWORK_SETUP_BLOCKED",
                    message=f"Workload pod '{pod_name}' later failed sandbox network setup on the same node",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Node-local CNI initialization failure is blocking workload pod networking",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Recognized node-local CNI pod '{cni_pod_name}' on node '{node_name}' has failing init container '{init_name}' with state={candidate['init_state_name']} restartCount={candidate['init_restart_count']}",
                f"Timeline shows {candidate['total_strength']} effective CNI-init-failure -> workload-network-block occurrence(s) within the last {self.WINDOW_MINUTES} minutes",
                f"Representative CNI init failure: {candidate['precursor_message']}",
                f"Representative workload symptom: {candidate['symptom_message']}",
            ],
            "object_evidence": {
                f"node:{node_name}": [
                    "A node-local CNI daemon failed during init/bootstrap before workload pod networking could be set up"
                ],
                f"pod:{cni_pod_name}": [
                    candidate["precursor_message"],
                ],
                f"pod:{pod_name}": [
                    candidate["symptom_message"],
                ],
            },
            "likely_causes": [
                "The node-local CNI DaemonSet could not finish its install/bootstrap step on the affected node",
                "The init container failed to render or copy CNI config or binaries under /etc/cni/net.d or the node plugin path",
                "A hostPath mount, permission issue, or image/problem in the CNI init container left the node without usable CNI bootstrap artifacts",
                "New workload pods on that node are blocked until the node-local CNI pod completes init successfully",
            ],
            "suggested_checks": [
                f"kubectl describe pod {cni_pod_name} -n {candidate['cni_namespace']}",
                f"kubectl logs -n {candidate['cni_namespace']} {cni_pod_name} -c {init_name}",
                f"kubectl describe pod {pod_name}",
                f"kubectl get pods -n {candidate['cni_namespace']} -o wide | findstr {node_name}",
            ],
        }
