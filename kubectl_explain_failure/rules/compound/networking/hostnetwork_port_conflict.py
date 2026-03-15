from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class HostNetworkPortConflictRule(FailureRule):
    """
    Detects Pod startup failures caused by port conflicts when hostNetwork=true.

    Signals:
    - Pod.spec.hostNetwork == True
    - Container exposes a port
    - Runtime events indicate port binding failure (address already in use)

    Interpretation:
    When hostNetwork is enabled, container ports bind directly to the node's
    network namespace. If the requested port is already used by another
    process or service on the node, the container runtime cannot start the
    Pod sandbox.

    Scope:
    - Runtime networking failure
    - Compound rule combining pod spec + runtime events
    """

    name = "HostNetworkPortConflict"
    category = "Compound"
    priority = 88
    deterministic = False

    blocks = ["HostPortConflict"]

    requires = {
        "pod": True,
    }

    def _collect_container_ports(self, pod):
        ports = []

        spec = pod.get("spec", {})
        containers = spec.get("containers", [])

        for c in containers:
            for p in c.get("ports", []) or []:
                port = p.get("containerPort")
                if port:
                    ports.append(port)

        return ports

    def matches(self, pod, events, context) -> bool:
        spec = pod.get("spec", {})

        if not spec.get("hostNetwork"):
            return False

        ports = self._collect_container_ports(pod)
        if not ports:
            return False

        timeline = context.get("timeline")

        for e in timeline.raw_events:
            msg = (e.get("message") or "").lower()

            if "address already in use" in msg:
                return True

            if "listen tcp" in msg and "bind" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        ports = self._collect_container_ports(pod)

        timeline = context.get("timeline") or build_timeline(events)

        evidence_msgs = []

        for e in timeline.events_within_window(15):
            msg = e.get("message")
            if not msg:
                continue

            lower = msg.lower()

            if "address already in use" in lower or "listen tcp" in lower:
                evidence_msgs.append(msg)

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        port_list = ", ".join(str(p) for p in ports)

        chain = CausalChain(
            causes=[
                Cause(
                    code="HOSTNETWORK_ENABLED",
                    message="Pod configured with hostNetwork=true",
                    role="runtime_context",
                ),
                Cause(
                    code="NODE_PORT_ALREADY_IN_USE",
                    message="Requested port already bound on the node network namespace",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_CREATION_FAILED",
                    message="Container runtime failed to bind port when starting pod sandbox",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod using hostNetwork cannot start because the requested port is already in use on the node",
            "confidence": 0.94,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.spec.hostNetwork=True",
                f"Container ports exposed: {port_list}",
                *evidence_msgs[:2],
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "hostNetwork=true",
                    f"containerPorts={port_list}",
                ]
            },
            "likely_causes": [
                "Another pod using hostNetwork already occupies the port",
                "A node-level service is bound to the same port",
                "DaemonSet running on the node uses the same port",
                "Host process is listening on the port",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pods -A -o wide | grep hostNetwork",
                "Check node processes listening on the port",
                "Verify no other workload uses the same host port",
            ],
        }
