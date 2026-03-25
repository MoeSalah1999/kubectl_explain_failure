from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class KubeletCertificateExpiredRule(FailureRule):
    """
    Detects node outages where kubelet client/server certificate validity
    prevents the kubelet from maintaining node status with the API server.

    Real-world interpretation:
    - Node Ready degrades to False or Unknown
    - Kubelet status/update/register operations fail with x509 expiry errors
    - Node-controller and kubelet events may show NotReady plus certificate
      validation failures
    - This is more specific than generic NodeNotReady or KubeletNotResponding
    """

    name = "KubeletCertificateExpired"
    category = "Node"
    priority = 27
    deterministic = True
    blocks = [
        "KubeletNotResponding",
        "NodeNotReady",
        "FailedScheduling",
    ]
    requires = {
        "objects": ["node"],
    }
    supported_phases = {"Pending", "Running", "Unknown"}

    CERT_MARKERS = (
        "x509: certificate has expired",
        "certificate has expired",
        "x509: certificate is not yet valid",
        "not yet valid",
    )

    KUBELET_STATUS_MARKERS = (
        "unable to register node",
        "failed to update node status",
        "failed to patch status",
        "error updating node status",
        "certificate rotation",
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

    def _condition_points_to_cert_expiry(self, node: dict) -> bool:
        cond = self._ready_condition(node)
        if not cond:
            return False

        status = str(cond.get("status", ""))
        message = str(cond.get("message", "")).lower()
        reason = str(cond.get("reason", "")).lower()

        if status not in {"False", "Unknown"}:
            return False
        if not any(marker in message for marker in self.CERT_MARKERS):
            return False

        return any(marker in message for marker in self.KUBELET_STATUS_MARKERS) or (
            "kubelet" in reason
        )

    def _has_certificate_timeline_signal(
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
            if not any(marker in message for marker in self.CERT_MARKERS):
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
        cert_expired_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_cert_expiry(node)
        }
        if not cert_expired_nodes:
            return False

        assigned_node = pod.get("spec", {}).get("nodeName")
        if assigned_node and assigned_node in cert_expired_nodes:
            return True

        return self._has_certificate_timeline_signal(events, context)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_objs = context.get("objects", {}).get("node", {})
        candidate_nodes = self._candidate_nodes(pod, node_objs)
        cert_expired_nodes = {
            name: node
            for name, node in candidate_nodes.items()
            if self._condition_points_to_cert_expiry(node)
        }

        node_names = sorted(cert_expired_nodes.keys())
        assigned_node = pod.get("spec", {}).get("nodeName")
        ready_status = "False"
        ready_reason = "KubeletNotReady"
        for node in cert_expired_nodes.values():
            cond = self._ready_condition(node)
            if cond:
                ready_status = str(cond.get("status", ready_status))
                ready_reason = str(cond.get("reason", ready_reason))
                break

        evidence = [
            f"Node Ready condition is {ready_status}",
            f"Ready condition reason: {ready_reason}",
            f"Affected node(s): {', '.join(node_names)}",
            "Certificate validity error is present in kubelet/node status signal",
        ]
        if assigned_node:
            evidence.append(f"Pod is assigned to node {assigned_node}")
        if self._has_certificate_timeline_signal(events, context):
            evidence.append(
                "Timeline contains kubelet or node-controller event showing x509 certificate validity failure"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="KUBELET_CERTIFICATE_INVALID",
                    message="Kubelet certificate is expired or not yet valid for API communication",
                    role="infrastructure_context",
                ),
                Cause(
                    code="KUBELET_CERTIFICATE_EXPIRED",
                    message="Kubelet cannot maintain node status because its certificate validity has failed",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="NODE_CONTROL_PLANE_LINK_DEGRADED",
                    message="Node health reporting and workload management are impaired by kubelet certificate failure",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            **{
                f"node:{name}": [
                    f"Ready condition={ready_status} reason={ready_reason} with certificate validity failure"
                ]
                for name in node_names
            },
            f"pod:{pod_name}": [
                "Pod is affected by kubelet certificate expiry on its node"
            ],
        }

        return {
            "root_cause": "Kubelet certificate expired or not yet valid",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet client certificate expired",
                "Certificate rotation failed or stalled",
                "Node clock skew makes the certificate appear not yet valid",
                "Kubelet cannot authenticate to the API server due to x509 validity failure",
            ],
            "suggested_checks": [
                (
                    f"kubectl describe node {node_names[0]}"
                    if node_names
                    else "kubectl describe node <node>"
                ),
                "Check kubelet certificate expiration and rotation status on the node",
                "Inspect kubelet logs for x509 or certificate rotation errors",
                f"kubectl describe pod {pod_name}",
            ],
        }
