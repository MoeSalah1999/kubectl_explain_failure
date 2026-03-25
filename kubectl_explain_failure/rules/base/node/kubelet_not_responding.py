from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class KubeletNotRespondingRule(FailureRule):
    """
    Detects nodes whose kubelet has stopped reporting status or heartbeats
    to the control plane, impacting assigned or pending workloads.

    Real-world interpretation:
    - Node Ready condition typically becomes Unknown
    - Condition reason/message indicates heartbeat loss or missing node status
    - Node controller emits NodeNotReady / node-status-unknown signals
    - This is more specific than generic NodeNotReady because it points to
      kubelet reachability / heartbeat failure rather than any NotReady cause
    """

    name = "KubeletNotResponding"
    category = "Node"
    priority = 26
    deterministic = True
    blocks = [
        "NodeNotReady",
        "FailedScheduling",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

    CONDITION_REASON_MARKERS = {
        "NodeStatusUnknown",
        "KubeletStoppedPostingStatus",
    }

    MESSAGE_MARKERS = (
        "kubelet stopped posting node status",
        "node status is unknown",
        "node status unknown",
        "failed to get node status",
        "stopped posting node status",
        "stopped posting status",
        "node lease",
        "heartbeat",
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

    def _is_kubelet_not_responding(self, node: dict) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        status = str(cond.get("status", ""))
        reason = str(cond.get("reason", ""))
        message = str(cond.get("message", "")).lower()

        if status not in {"False", "Unknown"}:
            return False

        if reason in self.CONDITION_REASON_MARKERS:
            return True

        return any(marker in message for marker in self.MESSAGE_MARKERS)

    def _has_kubelet_timeline_signal(self, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else events

        for event in raw_events:
            reason = str(event.get("reason", ""))
            message = str(event.get("message", "")).lower()

            if reason in self.CONDITION_REASON_MARKERS:
                return True

            if reason == "NodeNotReady" and any(
                marker in message for marker in self.MESSAGE_MARKERS
            ):
                return True

            if any(marker in message for marker in self.MESSAGE_MARKERS):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        kubelet_unresponsive_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._is_kubelet_not_responding(node)
        }
        if not kubelet_unresponsive_nodes:
            return False

        assigned_node = pod.get("spec", {}).get("nodeName")
        pod_phase = pod.get("status", {}).get("phase")

        if assigned_node and assigned_node in kubelet_unresponsive_nodes:
            return True

        if pod_phase == "Pending":
            return self._has_kubelet_timeline_signal(events, context)

        return self._has_kubelet_timeline_signal(events, context)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        kubelet_unresponsive_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._is_kubelet_not_responding(node)
        }

        node_names = sorted(kubelet_unresponsive_nodes.keys())
        assigned_node = pod.get("spec", {}).get("nodeName")

        ready_status = "Unknown"
        ready_reason = "NodeStatusUnknown"
        for node in kubelet_unresponsive_nodes.values():
            cond = self._ready_condition(node)
            if cond:
                ready_status = str(cond.get("status", ready_status))
                ready_reason = str(cond.get("reason", ready_reason))
                break

        evidence = [
            f"Node Ready condition is {ready_status}",
            f"Ready condition reason indicates kubelet status loss: {ready_reason}",
            f"Affected node(s): {', '.join(node_names)}",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")
        if self._has_kubelet_timeline_signal(events, context):
            evidence.append(
                "Timeline contains node-controller or status signal that kubelet stopped reporting"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="KUBELET_HEARTBEAT_MISSING",
                    message=f"Node Ready condition degraded with reason {ready_reason}",
                    role="infrastructure_context",
                ),
                Cause(
                    code="KUBELET_NOT_RESPONDING",
                    message="Kubelet stopped reporting node status to the control plane",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_IMPACTED_BY_KUBELET_CONTROL_LOSS",
                    message="Workload is affected because the node agent is no longer responding",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [
                    f"Ready condition={ready_status} reason={ready_reason}"
                ]
                for name in node_names
            },
            f"pod:{pod_name}": [
                "Pod is affected by kubelet heartbeat/status loss on its node"
            ],
        }

        return {
            "root_cause": "Kubelet is not responding on node",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet process is hung, stopped, or crashing",
                "Node cannot reach the API server to renew heartbeats or leases",
                "Node is overloaded enough that kubelet health reporting is failing",
                "Underlying host or VM networking is degraded",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "kubectl get nodes",
                "Check kubelet service health and logs on the node",
                "Inspect node heartbeat and lease renewal behavior",
                f"kubectl describe pod {pod_name}",
            ],
        }
