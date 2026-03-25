from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ContainerRuntimeVersionMismatchRule(FailureRule):
    """
    Detects node-level CRI incompatibility where kubelet can reach the
    container runtime socket, but the runtime API or version is unsupported.

    Real-world interpretation:
    - kubelet is running and attempting sandbox/runtime operations
    - the CRI endpoint responds, but with unsupported API/version semantics
    - common after kubelet/runtime upgrades or incompatible CRI versions
    - more specific than generic runtime unavailability
    """

    name = "ContainerRuntimeVersionMismatch"
    category = "Node"
    priority = 28
    deterministic = True
    blocks = [
        "ContainerRuntimeUnavailable",
        "NodeNotReady",
        "ContainerRuntimeStartFailure",
        "FailedScheduling",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

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
        "container runtime network not ready",
        "runtime service failed",
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

    def _condition_points_to_version_mismatch(self, node: dict) -> bool:
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

    def _has_version_timeline_signal(self, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else events

        for event in raw_events:
            source = event.get("source")
            if isinstance(source, dict):
                component = str(source.get("component", "")).lower()
            else:
                component = str(source or "").lower()
            message = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()

            if component and component != "kubelet":
                continue
            if not any(marker in message for marker in self.VERSION_MARKERS):
                continue
            if reason in {
                "failedcreatepodsandbox",
                "failed",
                "containerruntimeunhealthy",
            }:
                return True
            if any(marker in message for marker in self.STATUS_MARKERS):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        mismatch_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_version_mismatch(node)
        }
        if not mismatch_nodes:
            return False

        return self._has_version_timeline_signal(events, context)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        mismatch_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_version_mismatch(node)
        }

        node_names = sorted(mismatch_nodes.keys())
        assigned_node = pod.get("spec", {}).get("nodeName")
        ready_reason = "KubeletNotReady"
        for node in mismatch_nodes.values():
            cond = self._ready_condition(node)
            if cond:
                ready_reason = str(cond.get("reason", ready_reason))
                break

        evidence = [
            "Node Ready condition indicates container runtime API/version incompatibility",
            f"Affected node(s): {', '.join(node_names)}",
            f"Ready condition reason: {ready_reason}",
            "Timeline contains kubelet runtime signal showing CRI API/version mismatch",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CRI_API_INCOMPATIBILITY_DETECTED",
                    message="Kubelet reached the runtime endpoint but encountered an unsupported CRI API/version",
                    role="infrastructure_context",
                ),
                Cause(
                    code="CONTAINER_RUNTIME_VERSION_MISMATCH",
                    message="Node container runtime version or CRI API is incompatible with kubelet expectations",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_RUNTIME_OPERATIONS_FAIL",
                    message="Kubelet cannot create pod sandboxes or manage workloads due to runtime API mismatch",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [
                    f"Node runtime reports CRI API/version mismatch (Ready reason={ready_reason})"
                ]
                for name in node_names
            },
            f"pod:{pod_name}": [
                "Pod is blocked because kubelet and the node container runtime are version-incompatible"
            ],
        }

        return {
            "root_cause": "Container runtime version or CRI API mismatch on node",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet was upgraded but containerd/cri-o was left on an incompatible CRI version",
                "Runtime exposes an unsupported CRI API version for this kubelet release",
                "Node upgrade left kubelet and runtime components out of sync",
                "Runtime plugin or CRI shim version is incompatible with kubelet expectations",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "Check kubelet and container runtime versions on the node",
                "Inspect kubelet logs for CRI API/version compatibility errors",
                f"kubectl describe pod {pod_name}",
            ],
        }
