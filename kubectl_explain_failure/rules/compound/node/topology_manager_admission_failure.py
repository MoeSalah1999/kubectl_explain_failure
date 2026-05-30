from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class TopologyManagerAdmissionFailureRule(FailureRule):
    """
    Detect kubelet Topology Manager admission failures.

    Real-world behavior:
    - Scheduler may successfully bind the pod to a node.
    - Kubelet admission then invokes Topology Manager.
    - Under policies such as single-numa-node or restricted,
      all requested topology-aware resources must align.
    - If NUMA alignment cannot be satisfied, kubelet rejects
      pod admission and the pod remains Pending.

    Common affected resources:
    - Guaranteed CPU allocations (CPU Manager static policy)
    - HugePages
    - GPUs
    - SR-IOV devices
    - RDMA devices
    - FPGA / accelerator device plugins
    """

    name = "TopologyManagerAdmissionFailure"
    category = "Node / Scheduling"
    priority = 89
    deterministic = True

    blocks = []

    requires = {}

    supported_phases = {
        "Pending",
    }

    STRONG_MARKERS = (
        "topology affinity error",
        "topology manager",
        "topologymanager",
        "failed to admit pod",
    )

    NUMA_MARKERS = (
        "numa",
        "single-numa-node",
        "single numa node",
        "topology policy",
        "hint provider",
        "best topology hint",
        "affinity",
    )

    EXCLUSION_MARKERS = (
        "insufficient cpu",
        "insufficient memory",
        "insufficient ephemeral-storage",
        "node(s) had taint",
        "didn't match pod affinity",
        "didn't match pod anti-affinity",
        "persistentvolumeclaim",
        "pod has unbound immediate persistentvolumeclaims",
        "failed scheduling",
        "0/",
        "preemption",
    )

    TOPOLOGY_RESOURCE_HINTS = (
        "hugepages-",
        "nvidia.com/",
        "amd.com/",
        "intel.com/",
        "rdma/",
        "mlx5",
        "sriov",
        "openshift.io/",
        "fpga",
        "xilinx.com/",
        "habana.ai/",
        "aws.amazon.com/neuron",
    )

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_text(self, event: dict[str, Any]) -> str:
        return f"{self._event_reason(event)} " f"{self._event_message(event)}"

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _is_scheduler_failure(self, event: dict[str, Any]) -> bool:
        text = self._event_text(event)

        if any(marker in text for marker in self.EXCLUSION_MARKERS):
            return True

        component = self._event_component(event)

        if component == "default-scheduler":
            return True

        if self._event_reason(event) == "failedscheduling":
            return True

        return False

    def _is_topology_failure(self, event: dict[str, Any]) -> bool:
        text = self._event_text(event)

        if self._is_scheduler_failure(event):
            return False

        strong = any(marker in text for marker in self.STRONG_MARKERS)
        numa = any(marker in text for marker in self.NUMA_MARKERS)

        if "topology affinity error" in text:
            return True

        if "failed to admit pod" in text and ("topology" in text or "numa" in text):
            return True

        if "topology manager" in text and (
            "fail" in text or "reject" in text or "cannot" in text or "error" in text
        ):
            return True

        if strong and numa:
            return True

        return False

    def _resource_names(self, pod: dict[str, Any]) -> set[str]:
        names: set[str] = set()

        spec = pod.get("spec", {})

        containers = spec.get("containers", []) + spec.get("initContainers", [])

        for container in containers:
            resources = container.get("resources", {})

            for section in ("requests", "limits"):
                values = resources.get(section, {})

                if not isinstance(values, dict):
                    continue

                for name in values:
                    names.add(str(name).lower())

        return names

    def _has_guaranteed_cpu(self, pod: dict[str, Any]) -> bool:
        spec = pod.get("spec", {})

        containers = spec.get("containers", [])

        if not containers:
            return False

        for container in containers:
            resources = container.get("resources", {})

            requests = resources.get("requests", {})
            limits = resources.get("limits", {})

            cpu_request = requests.get("cpu")
            cpu_limit = limits.get("cpu")

            if cpu_request is None or cpu_limit is None or cpu_request != cpu_limit:
                return False

        return True

    def _has_topology_sensitive_resources(
        self,
        pod: dict[str, Any],
    ) -> bool:
        names = self._resource_names(pod)

        if self._has_guaranteed_cpu(pod):
            return True

        for resource in names:
            if resource.startswith("hugepages-"):
                return True

            if any(marker in resource for marker in self.TOPOLOGY_RESOURCE_HINTS):
                return True

            #
            # Device-plugin resources usually contain a domain.
            #
            if "/" in resource and resource not in {
                "cpu",
                "memory",
                "ephemeral-storage",
            }:
                return True

        return False

    def _node_name(self, pod: dict[str, Any]) -> str | None:
        node_name = pod.get("spec", {}).get("nodeName")
        if isinstance(node_name, str) and node_name:
            return node_name
        return None

    def _relevant_failure_events(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [e for e in events if self._is_topology_failure(e)]

    def matches(self, pod, events, context) -> bool:
        phase = pod.get("status", {}).get("phase")

        if phase != "Pending":
            return False

        failures = self._relevant_failure_events(events)

        if not failures:
            return False

        #
        # Require at least one kubelet-side topology signal.
        #
        kubelet_related = False

        for event in failures:
            component = self._event_component(event)

            if component == "kubelet" or component == "":
                kubelet_related = True
                break

        return kubelet_related

    def explain(self, pod, events, context):
        failures = self._relevant_failure_events(events)

        if not failures:
            raise ValueError(
                "TopologyManagerAdmissionFailure explain() called without match"
            )

        failure = failures[0]

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        node_name = self._node_name(pod) or "<unspecified>"

        topology_sensitive = self._has_topology_sensitive_resources(pod)

        resources = sorted(self._resource_names(pod))

        confidence = 0.92

        if topology_sensitive:
            confidence = 0.98

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_MANAGER_EVALUATION",
                    message=("Kubelet Topology Manager evaluated NUMA placement"),
                    role="control_loop",
                ),
                Cause(
                    code="NUMA_ALIGNMENT_FAILURE",
                    message=(
                        "No valid topology-aligned resource placement could be found"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_ADMISSION_REJECTED",
                    message=("Kubelet rejected pod admission on the selected node"),
                    role="node_admission",
                ),
                Cause(
                    code="POD_STUCK_PENDING",
                    message=(
                        "Pod cannot start because topology admission never succeeded"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        message = str(failure.get("message", "")).strip()

        return {
            "root_cause": (
                "Topology Manager could not satisfy NUMA-alignment "
                "requirements for the pod's requested resources"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Kubelet emitted a topology admission failure",
                f"Pod is assigned to node {node_name}",
                "Pod remains in phase Pending",
                *(
                    ["Pod requests topology-sensitive resources"]
                    if topology_sensitive
                    else []
                ),
                *(["Event: " + message] if message else []),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod admission was rejected by Topology Manager",
                    *([message] if message else []),
                ]
            },
            "likely_causes": [
                "single-numa-node policy could not satisfy CPU and device locality requirements",
                "Guaranteed CPU allocation conflicts with available NUMA placement",
                "HugePages and CPU allocations reside on different NUMA nodes",
                "GPU locality requirements cannot be aligned with CPU allocation",
                "SR-IOV or RDMA device placement conflicts with NUMA policy",
                "NUMA fragmentation from existing workloads prevents a valid placement",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe node {node_name}",
                "Inspect kubelet logs for Topology Manager admission failures",
                "Review topologyManagerPolicy in kubelet configuration",
                "Check CPU Manager static-policy allocations",
                "Inspect NUMA layout using numactl --hardware",
                "Review hugepage allocation per NUMA node",
                "Verify GPU, SR-IOV, RDMA, or device-plugin locality constraints",
            ],
            "diagnostics": {
                "topology_sensitive_resources": topology_sensitive,
                "requested_resources": resources,
                "node_assigned": node_name != "<unspecified>",
                "failure_reason": failure.get("reason"),
            },
        }
