from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule


class PodSchedulingGateBlockedRule(FailureRule):
    """
    Detects Pods intentionally held out of scheduler placement by scheduling gates.

    Real-world behavior:
    - spec.schedulingGates is an explicit PodSchedulingReadiness hold
    - while the list is non-empty, the Pod stays SchedulingGated and the
      scheduler does not attempt node placement
    - gates can be set only at Pod creation and removed afterwards; a gated Pod
      is therefore not a capacity failure until all gates are cleared
    """

    name = "PodSchedulingGateBlocked"
    category = "Scheduling"
    priority = 90
    deterministic = True
    phases = ["Pending", "Unknown"]
    blocks = [
        "FailedScheduling",
        "PendingUnschedulable",
        "InsufficientResources",
        "UnschedulableTaint",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "PodAntiAffinityDeadlock",
        "PodTopologySpreadLabelMismatch",
        "TopologySpreadUnsatisfiable",
        "TopologySpreadSkewTooHigh",
        "TopologyKeyMissing",
        "HostPortConflict",
        "HostPortAlreadyAllocated",
        "ExtendedResourceUnavailable",
        "PodOverheadExceededNodeCapacity",
        "VolumeNodeAffinityConflict",
        "NodeUnschedulableCordoned",
        "NodeFragmentationPreventsPreemption",
        "PreemptionIneffectiveAffinity",
        "PreemptionIneffectivePDB",
        "PreemptionIneffectiveTopologySpread",
        "SchedulerExtenderFailure",
        "RuntimeClassNotFound",
    ]

    requires = {
        "pod": True,
    }

    def _gate_names(self, pod: dict[str, Any]) -> list[str]:
        gates = pod.get("spec", {}).get("schedulingGates") or []
        if not isinstance(gates, list):
            return []

        names = []
        for gate in gates:
            if isinstance(gate, dict):
                name = gate.get("name")
            else:
                name = gate
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
        return names

    def _pod_scheduled_condition(self, pod: dict[str, Any]) -> dict[str, Any] | None:
        for condition in pod.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == "PodScheduled":
                return condition
        return None

    def _is_scheduled(self, pod: dict[str, Any]) -> bool:
        spec = pod.get("spec", {}) or {}
        if spec.get("nodeName"):
            return True

        condition = self._pod_scheduled_condition(pod)
        if not condition:
            return False
        return str(condition.get("status", "")).lower() == "true"

    def _status_reason_is_gated(self, pod: dict[str, Any]) -> bool:
        status = pod.get("status", {}) or {}
        if status.get("reason") == "SchedulingGated":
            return True

        condition = self._pod_scheduled_condition(pod)
        if not condition:
            return False
        return condition.get("reason") == "SchedulingGated"

    def _gated_events(self, events: list[dict[str, Any]]) -> list[str]:
        messages = []
        for event in events or []:
            reason = str(event.get("reason") or "")
            message = str(event.get("message") or "")
            combined = f"{reason} {message}".lower()
            if "schedulinggated" not in combined and "scheduling gate" not in combined:
                continue
            if message:
                messages.append(message)
        return messages

    def matches(self, pod, events, context) -> bool:
        if self._is_scheduled(pod):
            return False

        phase = get_pod_phase(pod)
        if phase not in {"Pending", "Unknown"}:
            return False

        if self._gate_names(pod):
            return True

        return self._status_reason_is_gated(pod)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        gate_names = self._gate_names(pod)
        gate_display = ", ".join(gate_names) if gate_names else "<unknown>"
        gated_event_messages = self._gated_events(events)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SCHEDULING_GATES_PRESENT",
                    message=f"Pod has active scheduling gate(s): {gate_display}",
                    role="workload_context",
                ),
                Cause(
                    code="SCHEDULER_PLACEMENT_HELD",
                    message="Kubernetes scheduler will not attempt node placement while scheduling gates remain",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_REMAINS_SCHEDULING_GATED",
                    message="Pod remains Pending/SchedulingGated until the responsible controller removes all gates",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
        ]
        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                "Pod is not bound to a node",
            ]
        }

        if gate_names:
            evidence.append(f"Pod.spec.schedulingGates={gate_display}")
            object_evidence[f"pod:{namespace}/{pod_name}"].append(
                f"Active scheduling gate(s): {gate_display}"
            )

        condition = self._pod_scheduled_condition(pod)
        if condition:
            reason = condition.get("reason", "<unknown>")
            status = condition.get("status", "<unknown>")
            evidence.append(f"PodScheduled condition status={status} reason={reason}")
            object_evidence[f"pod:{namespace}/{pod_name}"].append(
                f"PodScheduled={status} reason={reason}"
            )

        if gated_event_messages:
            evidence.extend(gated_event_messages[:2])
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(
                gated_event_messages[:3]
            )

        return {
            "rule": self.name,
            "root_cause": "Pod is blocked by active scheduling gates",
            "confidence": 0.98 if gate_names else 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "A custom controller or admission workflow added scheduling gates and has not removed them",
                "The controller responsible for readiness orchestration is delayed, unhealthy, or missing permissions",
                "A rollout, quota, placement, or external capacity precondition has not completed",
                "The Pod manifest was created with a gate name that no controller recognizes",
            ],
            "suggested_checks": [
                f"kubectl get pod {pod_name} -n {namespace} -o jsonpath='{{.spec.schedulingGates}}'",
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Identify the controller or webhook that owns each scheduling gate name",
                "Check controller logs and RBAC permissions for removing spec.schedulingGates",
                "Remove stale gates only after confirming the required scheduling preconditions are satisfied",
            ],
        }
