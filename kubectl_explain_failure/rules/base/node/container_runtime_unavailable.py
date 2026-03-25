from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ContainerRuntimeUnavailableRule(FailureRule):
    """
    Detects node-level container runtime outages where kubelet is still
    running but cannot reach or use the CRI runtime service.

    Real-world interpretation:
    - kubelet remains active enough to emit pod-sandbox/runtime errors
    - node Ready often becomes False with KubeletNotReady
    - condition/event messages mention containerd/cri-o or runtime endpoint
      unavailability
    - this is broader than a single container failing to start; the node's
      runtime service itself is unavailable
    """

    name = "ContainerRuntimeUnavailable"
    category = "Node"
    priority = 25
    deterministic = True
    blocks = [
        "NodeNotReady",
        "FailedScheduling",
        "ContainerRuntimeStartFailure",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

    RUNTIME_MARKERS = (
        "container runtime is down",
        "container runtime is not running",
        "container runtime status check may not have completed yet",
        "runtime service failed",
        "failed to connect to container runtime",
        "failed to get runtime status",
        "failed to create pod sandbox",
        "failed to create sandbox",
        "containerd.sock",
        "cri-o.sock",
        "runtime.v1.runtimeservice",
        "rpc error: code = unavailable",
        "connection refused",
    )

    HEARTBEAT_ONLY_MARKERS = (
        "kubelet stopped posting node status",
        "node status is unknown",
        "node status unknown",
        "heartbeat",
        "node lease",
    )

    def _candidate_nodes(
        self, pod: dict, node_objs: dict[str, dict]
    ) -> dict[str, dict]:
        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in node_objs:
            return {assigned_node: node_objs[assigned_node]}
        return node_objs

    def _ready_condition(self, node: dict) -> dict | None:
        for cond in node.get("status", {}).get("conditions", []):
            if cond.get("type") == "Ready":
                return cond
        return None

    def _condition_points_to_runtime_outage(self, node: dict) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        status = str(cond.get("status", ""))
        reason = str(cond.get("reason", ""))
        message = str(cond.get("message", "")).lower()

        if status not in {"False", "Unknown"}:
            return False

        if reason == "NodeStatusUnknown":
            return False
        if any(marker in message for marker in self.HEARTBEAT_ONLY_MARKERS):
            return False

        return any(marker in message for marker in self.RUNTIME_MARKERS)

    def _has_runtime_timeline_signal(self, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else events

        for event in raw_events:
            reason = str(event.get("reason", "")).lower()
            source = event.get("source")
            if isinstance(source, dict):
                component = str(source.get("component", "")).lower()
            else:
                component = str(source or "").lower()
            message = str(event.get("message", "")).lower()

            if component and component not in {"kubelet", "node-controller"}:
                continue
            if any(marker in message for marker in self.HEARTBEAT_ONLY_MARKERS):
                continue

            if reason in {
                "failedcreatepodsandbox",
                "failed",
                "containerruntimeunhealthy",
            }:
                if any(marker in message for marker in self.RUNTIME_MARKERS):
                    return True

            if any(marker in message for marker in self.RUNTIME_MARKERS):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        runtime_unavailable_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_runtime_outage(node)
        }
        if not runtime_unavailable_nodes:
            return False

        if not self._has_runtime_timeline_signal(events, context):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        runtime_unavailable_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_runtime_outage(node)
        }

        node_names = sorted(runtime_unavailable_nodes.keys())
        assigned_node = pod.get("spec", {}).get("nodeName")
        ready_reason = "KubeletNotReady"
        for node in runtime_unavailable_nodes.values():
            cond = self._ready_condition(node)
            if cond:
                ready_reason = str(cond.get("reason", ready_reason))
                break

        evidence = [
            "Node Ready condition indicates container runtime outage",
            f"Affected node(s): {', '.join(node_names)}",
            f"Ready condition reason: {ready_reason}",
            "Timeline contains kubelet/runtime signal that CRI endpoint is unavailable",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_RUNTIME_ENDPOINT_UNREACHABLE",
                    message="Kubelet cannot reach the node container runtime service",
                    role="infrastructure_context",
                ),
                Cause(
                    code="CONTAINER_RUNTIME_UNAVAILABLE",
                    message="Node container runtime is unavailable for sandbox and container operations",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_RUNTIME_OPERATIONS_BLOCKED",
                    message="Kubelet cannot create pod sandboxes or start workloads while runtime is down",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [
                    f"Node runtime unavailable (Ready reason={ready_reason})"
                ]
                for name in node_names
            },
            f"pod:{pod_name}": [
                "Pod is blocked because kubelet cannot use the node container runtime"
            ],
        }

        return {
            "root_cause": "Container runtime unavailable on node",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "containerd or cri-o service is stopped or crashed",
                "Kubelet cannot connect to the CRI socket",
                "Node runtime upgrade or reconfiguration left the runtime unavailable",
                "Underlying host issues are preventing the runtime daemon from starting",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "Check containerd/cri-o service status on the node",
                "Inspect kubelet logs for CRI connection errors",
                f"kubectl describe pod {pod_name}",
            ],
        }
