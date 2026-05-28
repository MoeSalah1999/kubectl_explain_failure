from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DevicePluginUnavailableRule(FailureRule):
    """
    Detects Pods blocked because required Kubernetes device plugins
    disappeared, crashed, stopped advertising resources, or are unavailable
    on target nodes.

    Real-world behavior:
    - GPU/FPGA/Inferentia/TPU workloads request extended resources
    - scheduler may fail because allocatable resources vanished
    - kubelet may fail container creation after plugin deregistration
    - node allocatable resources may suddenly drop to zero
    - device-plugin DaemonSets often crash after:
        * driver upgrades
        * node reboot
        * runtime upgrade
        * kernel mismatch
        * GPU reset
        * plugin DaemonSet rollout failure
    - common examples:
        * nvidia.com/gpu
        * amd.com/gpu
        * intel.com/fpga
        * aws.amazon.com/neuron
        * habana.ai/gaudi
    """

    name = "DevicePluginUnavailable"
    category = "Compound"
    priority = 83
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "daemonset",
            "pod",
        ],
    }

    blocks = [
        "FailedScheduling",
        "InsufficientResources",
        "FailedCreatePodSandBox",
        "ContainerRuntimeUnavailable",
        "PendingUnschedulable",
        "CreateContainerError",
    ]

    RECENT_WINDOW_MINUTES = 30
    CACHE_KEY = "_device_plugin_unavailable_candidate"

    DEVICE_RESOURCE_MARKERS = (
        "nvidia.com/gpu",
        "amd.com/gpu",
        "gpu",
        "fpga",
        "inferentia",
        "neuron",
        "habana.ai",
        "gaudi",
        "tpu",
        "xilinx",
        "device plugin",
        "extended resource",
    )

    DEVICE_PLUGIN_FAILURE_MARKERS = (
        "failed to allocate device",
        "device plugin",
        "unhealthy devices",
        "failed to get device plugin",
        "no devices available",
        "no healthy devices",
        "failed to register device plugin",
        "device plugin registration",
        "failed to initialize nvml",
        "nvml",
        "nvidia-smi",
        "could not load nvml",
        "failed to dial device plugin",
        "grpc",
        "resource not found",
        "unexpected admission error",
        "allocation failed",
        "plugin socket",
        "failed to serve device plugin",
        "listandwatch",
        "device plugin disconnected",
        "device plugin stopped",
        "failed to contact device plugin",
        "failed to get allocation from device plugin",
    )

    SCHEDULING_MARKERS = (
        "insufficient nvidia.com/gpu",
        "insufficient amd.com/gpu",
        "insufficient",
        "didn't have enough resource",
        "did not have enough resource",
        "0/",
    )

    DEVICE_PLUGIN_POD_MARKERS = (
        "nvidia-device-plugin",
        "gpu-feature-discovery",
        "device-plugin",
        "kubelet-device-plugin",
        "neuron-device-plugin",
        "amd-gpu",
        "intel-device-plugins",
        "habana",
    )

    WAITING_REASONS = {
        "ContainerCreating",
        "CreateContainerError",
        "RunContainerError",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None

        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return self._parse_timestamp(
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")

        if isinstance(source, dict):
            return str(source.get("component") or "").lower()

        return str(source or "").lower()

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        indexed = list(
            enumerate(timeline.events_within_window(self.RECENT_WINDOW_MINUTES))
        )

        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _requested_extended_resources(
        self,
        pod: dict[str, Any],
    ) -> dict[str, str]:
        """
        Returns extended resource requests.

        Extended resources conventionally contain a slash and are not
        native kubernetes resources.
        """

        native_resources = {
            "cpu",
            "memory",
            "ephemeral-storage",
            "storage",
            "pods",
        }

        found: dict[str, str] = {}

        spec = pod.get("spec", {}) or {}

        for container_group in (
            "containers",
            "initContainers",
        ):
            for container in spec.get(container_group, []) or []:
                resources = container.get("resources", {}) or {}

                for section in ("requests", "limits"):
                    values = resources.get(section, {}) or {}

                    for resource_name, value in values.items():
                        resource_name = str(resource_name)

                        if (
                            "/" in resource_name
                            and resource_name not in native_resources
                        ):
                            found[resource_name] = str(value)

        return found

    def _pod_currently_impacted(self, pod: dict[str, Any]) -> bool:
        phase = get_pod_phase(pod)

        if phase == "Pending":
            return True

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}

            if waiting.get("reason") in self.WAITING_REASONS:
                return True

        return False

    def _event_targets_pod(
        self,
        event: dict[str, Any],
        pod_name: str,
    ) -> bool:
        involved = event.get("involvedObject")

        if isinstance(involved, dict):
            if (
                str(involved.get("kind") or "").lower() == "pod"
                and involved.get("name") == pod_name
            ):
                return True

        return pod_name.lower() in self._message(event).lower()

    def _event_targets_node(
        self,
        event: dict[str, Any],
        node_name: str,
    ) -> bool:
        involved = event.get("involvedObject")

        if isinstance(involved, dict):
            if (
                str(involved.get("kind") or "").lower() == "node"
                and involved.get("name") == node_name
            ):
                return True

            if involved.get("nodeName") == node_name:
                return True

        return node_name.lower() in self._message(event).lower()

    def _node_name(self, pod: dict[str, Any]) -> str | None:
        node_name = pod.get("spec", {}).get("nodeName")

        if node_name:
            return str(node_name)

        return None

    def _is_device_plugin_failure(
        self,
        event: dict[str, Any],
        resource_names: set[str],
    ) -> bool:
        reason = self._reason(event).lower()
        message = self._message(event).lower()
        source = self._source_component(event)

        text = f"{reason} {message} {source}"

        if not any(marker in text for marker in self.DEVICE_PLUGIN_FAILURE_MARKERS):
            return False

        if resource_names:
            if any(resource.lower() in text for resource in resource_names):
                return True

        return any(marker in text for marker in self.DEVICE_RESOURCE_MARKERS)

    def _is_gpu_scheduling_failure(
        self,
        event: dict[str, Any],
        resource_names: set[str],
    ) -> bool:
        if self._reason(event) != "FailedScheduling":
            return False

        message = self._message(event).lower()

        if not any(marker in message for marker in self.SCHEDULING_MARKERS):
            return False

        if resource_names:
            return any(resource.lower() in message for resource in resource_names)

        return any(marker in message for marker in self.DEVICE_RESOURCE_MARKERS)

    def _plugin_pod_failures(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        failures = []

        for event in timeline.events_within_window(self.RECENT_WINDOW_MINUTES):
            reason = self._reason(event).lower()
            message = self._message(event).lower()

            text = f"{reason} {message}"

            if not any(marker in text for marker in self.DEVICE_PLUGIN_POD_MARKERS):
                continue

            if reason in {
                "backoff",
                "failed",
                "unhealthy",
                "failedmount",
            }:
                failures.append(event)
                continue

            if any(
                marker in text
                for marker in (
                    "crashloopbackoff",
                    "error",
                    "failed",
                    "unhealthy",
                )
            ):
                failures.append(event)

        return failures

    def _node_allocatable_missing_resource(
        self,
        node: dict[str, Any],
        resource_names: set[str],
    ) -> list[str]:
        allocatable = node.get("status", {}).get("allocatable", {}) or {}

        capacity = node.get("status", {}).get("capacity", {}) or {}

        evidence = []

        for resource in resource_names:
            alloc = allocatable.get(resource)
            cap = capacity.get(resource)

            if cap and (alloc in {None, "0", 0}):
                evidence.append(
                    f"Node advertises capacity for '{resource}' but allocatable is missing or zero"
                )

        return evidence

    def _correlation(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not self._pod_currently_impacted(pod):
            return None

        resources = self._requested_extended_resources(pod)

        if not resources:
            return None

        resource_names = set(resources)

        ordered = self._ordered_events(timeline)

        pod_name = str(pod.get("metadata", {}).get("name") or "")

        node_name = self._node_name(pod)

        scheduling_failures = []
        plugin_failures = []

        for event in ordered:
            if self._is_gpu_scheduling_failure(
                event,
                resource_names,
            ):
                if self._event_targets_pod(event, pod_name) or not pod_name:
                    scheduling_failures.append(event)

            if self._is_device_plugin_failure(
                event,
                resource_names,
            ):
                if (
                    (node_name and self._event_targets_node(event, node_name))
                    or self._event_targets_pod(event, pod_name)
                    or not node_name
                ):
                    plugin_failures.append(event)

        daemonset_failures = self._plugin_pod_failures(timeline)

        node_evidence = []

        if node_name:
            nodes = context.get("objects", {}).get("node", {}) or {}

            node = nodes.get(node_name)

            if isinstance(node, dict):
                node_evidence.extend(
                    self._node_allocatable_missing_resource(
                        node,
                        resource_names,
                    )
                )

        if (
            not scheduling_failures
            and not plugin_failures
            and not daemonset_failures
            and not node_evidence
        ):
            return None

        representative = (
            plugin_failures[-1]
            if plugin_failures
            else (
                scheduling_failures[-1]
                if scheduling_failures
                else (daemonset_failures[-1] if daemonset_failures else None)
            )
        )

        return {
            "resources": resources,
            "resource_names": sorted(resource_names),
            "scheduling_failures": scheduling_failures,
            "plugin_failures": plugin_failures,
            "daemonset_failures": daemonset_failures,
            "node_evidence": node_evidence,
            "representative": representative,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return False

        candidate = self._correlation(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._correlation(
            pod,
            context.get("timeline"),
            context,
        )

        if candidate is None:
            raise ValueError("DevicePluginUnavailable explain() called without match")

        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("DevicePluginUnavailable requires Timeline context")

        metadata = pod.get("metadata", {}) or {}

        pod_name = str(metadata.get("name") or "<unknown>")
        namespace = str(metadata.get("namespace") or "default")

        resource_display = ", ".join(candidate["resource_names"])

        representative = candidate["representative"]

        representative_message = (
            self._message(representative)
            if representative
            else "device plugin failure signals observed"
        )

        duration_seconds = timeline.duration_between(
            lambda event: (
                self._is_device_plugin_failure(
                    event,
                    set(candidate["resource_names"]),
                )
                or self._is_gpu_scheduling_failure(
                    event,
                    set(candidate["resource_names"]),
                )
            )
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_REQUIRES_DEVICE_PLUGIN_RESOURCE",
                    message=f"Pod requests extended hardware resource(s): {resource_display}",
                    role="scheduling_context",
                ),
                Cause(
                    code="DEVICE_PLUGIN_UNAVAILABLE",
                    message="The node device plugin stopped advertising or serving required hardware resources",
                    role="workload_root",
                    blocking=True,
                ),
                Cause(
                    code="EXTENDED_RESOURCES_UNAVAILABLE",
                    message="Requested GPU/FPGA/accelerator resources are unavailable to kubelet or scheduler",
                    role="resource_intermediate",
                ),
                Cause(
                    code="WORKLOAD_CANNOT_START_OR_SCHEDULE",
                    message="Pod cannot schedule or initialize because required hardware devices are unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} requests hardware resource(s): {resource_display}",
            f"Representative device-plugin failure: {representative_message}",
        ]

        if candidate["scheduling_failures"]:
            evidence.append(
                f"Observed {len(candidate['scheduling_failures'])} scheduler failure event(s) related to hardware resource exhaustion/unavailability"
            )

        if candidate["plugin_failures"]:
            evidence.append(
                f"Observed {len(candidate['plugin_failures'])} device-plugin runtime failure event(s)"
            )

        if candidate["daemonset_failures"]:
            evidence.append(
                "Device-plugin DaemonSet or plugin pod failures were observed in the same time window"
            )

        if duration_seconds:
            evidence.append(
                f"Device-plugin failures persisted for {duration_seconds / 60.0:.1f} minutes"
            )

        evidence.extend(candidate["node_evidence"])

        object_evidence = {
            f"pod:{pod_name}": [
                f"Pod requests extended resources: {resource_display}",
                representative_message,
            ],
        }

        if candidate["node_evidence"]:
            object_evidence["node:device-plugin"] = candidate["node_evidence"]

        if candidate["daemonset_failures"]:
            object_evidence["daemonset:device-plugin"] = [
                "Device plugin DaemonSet or plugin pods are unhealthy/crashing"
            ]

        return {
            "root_cause": "Required Kubernetes device plugin is unavailable or unhealthy",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "NVIDIA/AMD/FPGA device plugin DaemonSet crashed or was evicted",
                "GPU or accelerator drivers are missing, unhealthy, or incompatible with the kernel/runtime",
                "Node reboot or runtime upgrade caused the device plugin to deregister",
                "Device plugin socket registration with kubelet failed",
                "Hardware accelerator became unhealthy or disappeared from the node",
                "Extended resources are no longer advertised in node allocatable resources",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get nodes -o json",
                "kubectl describe node <node>",
                "kubectl -n kube-system get pods | grep -i device",
                "Inspect device-plugin DaemonSet logs and kubelet logs",
                "Verify GPU/FPGA drivers and runtime libraries are installed and healthy",
                "Check node allocatable/capacity for extended resources",
            ],
        }
