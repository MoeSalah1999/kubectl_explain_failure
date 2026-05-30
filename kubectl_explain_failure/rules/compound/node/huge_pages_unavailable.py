from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class HugePagesUnavailableRule(FailureRule):
    """
    Detect HugePages allocation failures.

    Real-world behavior:

    Scheduler path:
    - Pod requests hugepages-2Mi or hugepages-1Gi.
    - No node has sufficient free HugePages.
    - Scheduler emits Insufficient hugepages-*.

    Kubelet path:
    - Pod is assigned to a node.
    - NUMA / topology admission cannot satisfy HugePages locality.
    - Kubelet rejects admission.

    HugePages are pre-reserved and cannot be overcommitted,
    making this a hard blocking condition.
    """

    name = "HugePagesUnavailable"
    category = "Scheduling / Node"
    priority = 92
    deterministic = True

    blocks = [
        "TopologyManagerAdmissionFailure",
    ]

    requires = {}

    supported_phases = {
        "Pending",
    }

    HUGEPAGE_PREFIX = "hugepages-"

    STRONG_MARKERS = (
        "insufficient hugepages",
        "hugepages",
        "huge page",
        "hugepage",
    )

    TOPOLOGY_MARKERS = (
        "numa",
        "topology",
        "topology manager",
        "topology affinity error",
        "failed to admit pod",
        "single-numa-node",
    )

    EXCLUSION_MARKERS = (
        "insufficient memory",
        "insufficient cpu",
        "ephemeral-storage",
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

    def _requested_hugepages(
        self,
        pod: dict[str, Any],
    ) -> dict[str, str]:
        result: dict[str, str] = {}

        spec = pod.get("spec", {})

        containers = spec.get("containers", []) + spec.get("initContainers", [])

        for container in containers:
            resources = container.get("resources", {})

            for section in ("requests", "limits"):
                values = resources.get(section, {})

                if not isinstance(values, dict):
                    continue

                for resource_name, quantity in values.items():
                    lower = str(resource_name).lower()

                    if lower.startswith(self.HUGEPAGE_PREFIX):
                        result[lower] = str(quantity)

        return result

    def _pod_requests_hugepages(
        self,
        pod: dict[str, Any],
    ) -> bool:
        return bool(self._requested_hugepages(pod))

    def _scheduler_hugepage_failure(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = self._event_text(event)

        if self._event_reason(event) != "failedscheduling":
            return False

        return "insufficient hugepages" in text or "hugepages-" in text

    def _kubelet_hugepage_failure(
        self,
        event: dict[str, Any],
    ) -> bool:
        text = self._event_text(event)

        if "hugepages" not in text:
            return False

        if (
            "failed to admit pod" in text
            or "topology affinity error" in text
            or "topology manager" in text
        ):
            return True

        if "numa" in text and "hugepages" in text:
            return True

        return False

    def _failure_events(
        self,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        matches = []

        for event in events:
            if self._scheduler_hugepage_failure(event):
                matches.append(event)
                continue

            if self._kubelet_hugepage_failure(event):
                matches.append(event)

        return matches

    def _topology_related(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        for event in events:
            text = self._event_text(event)

            if any(marker in text for marker in self.TOPOLOGY_MARKERS):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        phase = pod.get("status", {}).get("phase")

        if phase != "Pending":
            return False

        if not self._pod_requests_hugepages(pod):
            return False

        return bool(self._failure_events(events))

    def explain(self, pod, events, context):
        failures = self._failure_events(events)

        if not failures:
            raise ValueError("HugePagesUnavailable explain() called without match")

        hugepages = self._requested_hugepages(pod)

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        node_name = pod.get("spec", {}).get("nodeName")

        topology_related = self._topology_related(failures)

        confidence = 0.99 if topology_related else 0.97

        evidence = []

        for resource, quantity in hugepages.items():
            evidence.append(f"Requested {resource}={quantity}")

        first_event = failures[0]
        message = str(first_event.get("message", "")).strip()

        if message:
            evidence.append(f"Event: {message}")

        chain = CausalChain(
            causes=[
                Cause(
                    code="HUGEPAGE_RESOURCE_REQUESTED",
                    message=("Workload requires preallocated HugePages"),
                    role="resource_requirement",
                ),
                Cause(
                    code="HUGEPAGES_UNAVAILABLE",
                    message=("Cluster cannot satisfy requested HugePages allocation"),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ADMISSION_OR_SCHEDULING_FAILED",
                    message=("Pod cannot be placed or admitted"),
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message=("Workload remains blocked waiting for HugePages"),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": ("Requested HugePages are unavailable on eligible nodes"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    *[f"{k}={v}" for k, v in hugepages.items()],
                    *([message] if message else []),
                ]
            },
            "likely_causes": [
                "No node has enough free hugepages-2Mi capacity",
                "No node has enough free hugepages-1Gi capacity",
                "HugePages were not preallocated during node boot",
                "Existing workloads already consumed available HugePages",
                "NUMA-local HugePages are exhausted under Topology Manager policy",
                "HugePages request exceeds node capacity",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "Check allocatable hugepages-2Mi and hugepages-1Gi resources",
                "Review scheduler FailedScheduling events",
                "Inspect kubelet topology-manager admission failures",
                "Verify HugePages kernel boot parameters",
                "Check NUMA-local HugePages availability on target nodes",
                "Compare requested HugePages size with node allocatable capacity",
            ],
            "diagnostics": {
                "requested_hugepages": hugepages,
                "node_assigned": bool(node_name),
                "topology_related": topology_related,
                "failure_reason": first_event.get("reason"),
            },
        }
