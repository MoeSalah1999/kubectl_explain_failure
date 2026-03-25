from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeClockSkewDetectedRule(FailureRule):
    """
    Detects node time drift that breaks kubelet certificate validity and
    control-plane communication.

    Real-world interpretation:
    - Node Ready degrades because kubelet TLS/auth operations fail
    - Messages indicate certificate "not yet valid" rather than expired
    - Error text shows current node time is before certificate validity
      window or explicitly mentions clock skew / time sync problems
    - This is more specific than generic kubelet certificate failure
    """

    name = "NodeClockSkewDetected"
    category = "Node"
    priority = 29
    deterministic = True
    blocks = [
        "KubeletCertificateExpired",
        "KubeletNotResponding",
        "NodeNotReady",
        "FailedScheduling",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

    NOT_YET_VALID_MARKERS = (
        "x509: certificate is not yet valid",
        "not yet valid",
    )

    CLOCK_SKEW_MARKERS = (
        "clock skew",
        "time is out of sync",
        "time drift",
        "current time",
        "is before",
        "ntp",
        "chrony",
    )

    KUBELET_STATUS_MARKERS = (
        "failed to update node status",
        "error updating node status",
        "unable to register node",
        "failed to patch status",
        "kubelet",
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

    def _condition_points_to_clock_skew(self, node: dict) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        status = str(cond.get("status", ""))
        reason = str(cond.get("reason", "")).lower()
        message = str(cond.get("message", "")).lower()

        if status not in {"False", "Unknown"}:
            return False
        if not any(marker in message for marker in self.NOT_YET_VALID_MARKERS):
            return False
        if not any(marker in message for marker in self.CLOCK_SKEW_MARKERS):
            return False

        return any(marker in message for marker in self.KUBELET_STATUS_MARKERS) or (
            "kubelet" in reason
        )

    def _has_clock_skew_timeline_signal(
        self, events: list[dict], context: dict
    ) -> bool:
        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else events

        for event in raw_events:
            source = event.get("source")
            if isinstance(source, dict):
                component = str(source.get("component", "")).lower()
            else:
                component = str(source or "").lower()
            reason = str(event.get("reason", "")).lower()
            message = str(event.get("message", "")).lower()

            if component and component not in {"kubelet", "node-controller"}:
                continue
            if not any(marker in message for marker in self.NOT_YET_VALID_MARKERS):
                continue
            if not any(marker in message for marker in self.CLOCK_SKEW_MARKERS):
                continue
            if any(marker in message for marker in self.KUBELET_STATUS_MARKERS):
                return True
            if reason in {"nodenotready", "kubeletnotready"}:
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        node_objs = context.get("objects", {}).get("node", {})
        if not node_objs:
            return False

        if any(str(event.get("reason", "")) == "Evicted" for event in events):
            return False

        candidate_nodes = self._candidate_nodes(pod, node_objs)
        skewed_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_clock_skew(node)
        }
        if not skewed_nodes:
            return False

        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in skewed_nodes:
            return True

        return self._has_clock_skew_timeline_signal(events, context)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        skewed_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_clock_skew(node)
        }

        node_names = sorted(skewed_nodes.keys())
        assigned_node = pod.get("spec", {}).get("nodeName")
        ready_status = "False"
        ready_reason = "KubeletNotReady"
        for node in skewed_nodes.values():
            cond = self._ready_condition(node)
            if cond:
                ready_status = str(cond.get("status", ready_status))
                ready_reason = str(cond.get("reason", ready_reason))
                break

        evidence = [
            f"Node Ready condition is {ready_status}",
            f"Ready condition reason: {ready_reason}",
            f"Affected node(s): {', '.join(node_names)}",
            "Kubelet certificate validity failure shows current node time is outside the certificate validity window",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")
        if self._has_clock_skew_timeline_signal(events, context):
            evidence.append(
                "Timeline contains kubelet or node-controller event indicating certificate is not yet valid due to node time skew"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_TIME_OUT_OF_SYNC",
                    message="Node clock is out of sync with control-plane certificate validity",
                    role="infrastructure_context",
                ),
                Cause(
                    code="NODE_CLOCK_SKEW_DETECTED",
                    message="Node clock skew breaks kubelet certificate validation and API communication",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_NODE_STATUS_UPDATES_FAIL",
                    message="Kubelet cannot reliably update node status while node time is invalid",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [
                    f"Ready condition={ready_status} reason={ready_reason} with time-validity failure"
                ]
                for name in node_names
            },
            f"pod:{pod_name}": [
                "Pod is affected because kubelet certificate validation is failing due to node clock skew"
            ],
        }

        return {
            "root_cause": "Node clock skew detected",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "NTP or chrony is not synchronizing node time",
                "Node clock drift makes kubelet certificates appear not yet valid",
                "Virtual machine host time drift propagated to the node",
                "Time synchronization service is stopped or misconfigured",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "Check node time synchronization status (NTP/chrony/systemd-timesyncd)",
                "Inspect kubelet logs for certificate not-yet-valid errors",
                f"kubectl describe pod {pod_name}",
            ],
        }
