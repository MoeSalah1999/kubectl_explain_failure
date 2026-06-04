from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base.scheduling.dynamic_resource_allocation_failed import (
    DynamicResourceAllocationFailedRule,
)
from kubectl_explain_failure.timeline import Timeline


class GPUDeviceAllocationFailedRule(DynamicResourceAllocationFailedRule):
    """
    Detects Pods blocked because GPU devices could not be allocated.

    Real-world behavior:
    - Classic GPU scheduling uses extended resources such as nvidia.com/gpu,
      nvidia.com/mig-*, amd.com/gpu, or gpu.intel.com/*.
    - DRA-based GPU scheduling uses ResourceClaims that reference GPU
      DeviceClasses and ResourceSlices.
    - Scheduler failures usually say "Insufficient <gpu resource>" or report no
      matching devices/slices. Kubelet/device-plugin failures may surface as
      failed Allocate calls, unhealthy devices, or topology admission errors.
    - A missing device plugin is a separate infrastructure issue handled by the
      compound DevicePluginUnavailable rule; this rule focuses on allocation
      and capacity failure for the affected workload.
    """

    name = "GPUDeviceAllocationFailed"
    category = "Scheduling"
    priority = 93
    deterministic = False
    phases = ["Pending", "Running", "Unknown"]
    blocks = [
        "DynamicResourceAllocationFailed",
        "ResourceClassDriverUnavailable",
        "ResourceClaimPending",
        "ExtendedResourceUnavailable",
        "InsufficientResources",
        "FailedScheduling",
        "PendingUnschedulable",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "UnschedulableTaint",
        "TopologyManagerAdmissionFailure",
        "ClusterAutoscalerScaleUpFailed",
    ]

    requires = {
        "pod": True,
        "optional_objects": [
            "node",
            "resourceclaim",
            "resourceclaimtemplate",
            "resourceclass",
            "deviceclass",
            "resourceslice",
        ],
    }

    CACHE_KEY = "_gpu_device_allocation_failed_candidate"
    WINDOW_MINUTES = 60

    GPU_RESOURCE_PREFIXES = (
        "nvidia.com/",
        "amd.com/",
        "gpu.intel.com/",
        "intel.com/gpu",
        "xilinx.com/",
    )
    GPU_RESOURCE_MARKERS = (
        "gpu",
        "mig-",
        "nvidia",
        "cuda",
        "amd.com/gpu",
        "rocm",
        "gpu.intel.com",
        "intel gpu",
    )
    GPU_FAILURE_MARKERS = (
        "insufficient",
        "didn't have enough resource",
        "did not have enough resource",
        "not enough",
        "no available gpu",
        "no gpus available",
        "no healthy gpu",
        "no healthy devices",
        "no matching gpu",
        "no suitable gpu",
        "failed to allocate gpu",
        "failed to allocate device",
        "allocate failed",
        "allocation failed",
        "device allocation failed",
        "could not allocate gpu",
        "unable to allocate gpu",
        "unexpected admission error",
        "topology affinity error",
        "gpu allocation",
        "mig allocation",
        "resource pool exhausted",
        "capacity exhausted",
        "no resourceslice",
        "no resource slice",
        "no matching resourceslice",
        "no matching resource slice",
        "device taint",
        "tainted device",
        "not tolerated",
    )
    STRONG_GPU_ALLOCATION_FAILURE_MARKERS = (
        "failed to allocate gpu",
        "failed to allocate device",
        "allocate failed",
        "allocation failed",
        "device allocation failed",
        "could not allocate gpu",
        "unable to allocate gpu",
        "unexpected admission error",
        "topology affinity error",
        "gpu allocation",
        "mig allocation",
        "resource pool exhausted",
        "capacity exhausted",
        "no resourceslice",
        "no resource slice",
        "no matching resourceslice",
        "no matching resource slice",
        "device taint",
        "tainted device",
        "not tolerated",
    )
    DEVICE_PLUGIN_UNAVAILABLE_ONLY = (
        "failed to register device plugin",
        "plugin socket",
        "device plugin disconnected",
        "device plugin stopped",
        "failed to dial device plugin",
        "could not load nvml",
        "failed to initialize nvml",
    )

    def _container_specs(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        spec = pod.get("spec", {}) or {}
        containers: list[dict[str, Any]] = []
        for key in ("initContainers", "containers"):
            containers.extend(c for c in spec.get(key, []) or [] if isinstance(c, dict))
        return containers

    def _gpu_extended_resource_requests(self, pod: dict[str, Any]) -> dict[str, str]:
        requests: dict[str, str] = {}

        for container in self._container_specs(pod):
            resources = container.get("resources", {}) or {}
            for section in ("requests", "limits"):
                values = resources.get(section, {}) or {}
                if not isinstance(values, dict):
                    continue
                for name, value in values.items():
                    resource_name = str(name)
                    lowered = resource_name.lower()
                    if self._is_gpu_resource_name(lowered):
                        requests[resource_name] = str(value)

        return requests

    def _is_gpu_resource_name(self, resource_name: str) -> bool:
        return (
            any(
                resource_name.startswith(prefix)
                for prefix in self.GPU_RESOURCE_PREFIXES
            )
            and any(marker in resource_name for marker in self.GPU_RESOURCE_MARKERS)
        ) or resource_name in {"nvidia.com/gpu", "amd.com/gpu"}

    def _is_gpu_text(self, text: str) -> bool:
        lowered = text.lower()
        return any(marker in lowered for marker in self.GPU_RESOURCE_MARKERS)

    def _event_text(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        component = source.get("component") if isinstance(source, dict) else source
        return " ".join(
            str(part or "")
            for part in (event.get("reason"), event.get("message"), component)
        ).lower()

    def _event_mentions_pod_name(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
    ) -> bool:
        return self._event_mentions_pod(
            event,
            pod_name=pod_name,
            pod_namespace=pod_namespace,
        )

    def _looks_gpu_allocation_failure_event(
        self,
        event: dict[str, Any],
        *,
        resource_names: set[str],
        dra_names: set[str],
    ) -> bool:
        text = self._event_text(event)

        if any(marker in text for marker in self.NOT_FOUND_MARKERS):
            return False

        if any(marker in text for marker in self.DEVICE_PLUGIN_UNAVAILABLE_ONLY):
            return False

        mentions_known_resource = any(
            resource.lower() in text for resource in resource_names
        )
        mentions_known_dra = any(name.lower() in text for name in dra_names if name)
        mentions_gpu = self._is_gpu_text(text)
        has_failure = any(marker in text for marker in self.GPU_FAILURE_MARKERS)
        has_strong_allocation_failure = any(
            marker in text for marker in self.STRONG_GPU_ALLOCATION_FAILURE_MARKERS
        )

        if not has_failure:
            return False

        if mentions_known_dra:
            return True

        if mentions_known_resource and has_strong_allocation_failure:
            return True

        if mentions_gpu and (
            has_strong_allocation_failure
            or "allocate" in text
            or "admission" in text
            or "resourceslice" in text
        ):
            return True

        return False

    def _candidate_events(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        timeline = context.get("timeline")
        if isinstance(timeline, Timeline):
            recent = timeline.events_within_window(self.WINDOW_MINUTES)
            return recent or timeline.events
        return events or []

    def _matching_gpu_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
        *,
        resource_names: set[str],
        dra_names: set[str],
    ) -> list[dict[str, Any]]:
        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        pod_namespace = self._namespace(pod)
        matches = []

        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue
            if not self._looks_gpu_allocation_failure_event(
                event,
                resource_names=resource_names,
                dra_names=dra_names,
            ):
                continue
            if not self._event_mentions_pod_name(
                event,
                pod_name=pod_name,
                pod_namespace=pod_namespace,
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            matches.append(event)

        return matches

    def _node_objects(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        return self._object_list(context, "node", "nodes")

    def _parse_quantity(self, value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)

        raw = str(value).strip()
        if not raw:
            return 0.0

        try:
            return float(raw)
        except ValueError:
            pass

        suffixes = {
            "k": 1_000,
            "m": 1_000_000,
            "g": 1_000_000_000,
            "ki": 1024,
            "mi": 1024**2,
            "gi": 1024**3,
        }
        lowered = raw.lower()
        for suffix, multiplier in suffixes.items():
            if lowered.endswith(suffix):
                try:
                    return float(lowered[: -len(suffix)]) * multiplier
                except ValueError:
                    return 0.0
        return 0.0

    def _resource_request_total(self, requests: dict[str, str], resource: str) -> float:
        return self._parse_quantity(requests.get(resource))

    def _node_gpu_capacity_signals(
        self,
        context: dict[str, Any],
        gpu_requests: dict[str, str],
    ) -> list[str]:
        nodes = self._node_objects(context)
        if not nodes or not gpu_requests:
            return []

        signals = []
        for resource in gpu_requests:
            allocatable_values = []
            capacity_values = []
            for node in nodes:
                status = node.get("status", {}) or {}
                allocatable_values.append(
                    self._parse_quantity(
                        (status.get("allocatable") or {}).get(resource)
                    )
                )
                capacity_values.append(
                    self._parse_quantity((status.get("capacity") or {}).get(resource))
                )

            total_allocatable = sum(allocatable_values)
            total_capacity = sum(capacity_values)
            requested = self._resource_request_total(gpu_requests, resource)

            if total_capacity == 0:
                signals.append(f"No node advertises GPU resource {resource}")
            elif total_allocatable == 0:
                signals.append(
                    f"GPU resource {resource} has cluster capacity but zero allocatable devices"
                )
            elif requested and max(allocatable_values or [0.0]) < requested:
                signals.append(
                    f"No node has {requested:g} allocatable {resource} device(s) for this Pod"
                )

        return signals

    def _gpu_dra_records(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        records = self._class_records(pod, context)
        gpu_records = []

        for record in records:
            text_parts = []
            for key in ("class_name", "driver"):
                value = record.get(key)
                if isinstance(value, str):
                    text_parts.append(value)

            for value in record.get("device_class_names", []) or []:
                text_parts.append(str(value))

            for device_class in record.get("device_classes", []) or []:
                if isinstance(device_class, dict):
                    text_parts.append(str(device_class.get("metadata", {})))
                    text_parts.append(str(device_class.get("spec", {})))

            claim = record.get("claim")
            template = record.get("template")
            if isinstance(claim, dict):
                text_parts.append(str(claim.get("spec", {})))
                text_parts.append(str(claim.get("status", {})))
            if isinstance(template, dict):
                text_parts.append(str(template.get("spec", {})))

            if self._is_gpu_text(" ".join(text_parts)):
                gpu_records.append(record)

        return gpu_records

    def _dra_name_set(self, records: list[dict[str, Any]]) -> set[str]:
        names = set()
        for record in records:
            for key in ("class_name", "driver"):
                value = record.get(key)
                if isinstance(value, str) and value:
                    names.add(value)
            for value in record.get("device_class_names", []) or []:
                names.add(str(value))
            ref = record.get("ref") or {}
            for key in ("logical_name", "claim_name", "template_name"):
                value = ref.get(key)
                if isinstance(value, str) and value:
                    names.add(value)
        return names

    def _dra_gpu_failure_signals(
        self,
        context: dict[str, Any],
        records: list[dict[str, Any]],
    ) -> list[str]:
        signals = []
        device_class_names = self._deviceclass_names_from_records(records)
        resource_slice_counts = self._resource_slice_count_for_device_classes(
            context,
            device_class_names,
        )

        for record in records:
            claim = record.get("claim")
            if isinstance(claim, dict):
                signals.extend(self._claim_allocation_failed(claim))

            for device_class_name in record.get("device_class_names", []) or []:
                if (
                    resource_slice_counts
                    and resource_slice_counts.get(device_class_name) == 0
                ):
                    signals.append(
                        f"No ResourceSlice advertises GPU devices for DeviceClass {device_class_name}"
                    )

        return list(dict.fromkeys(signals))

    def _pod_has_gpu_waiting_state(self, pod: dict[str, Any]) -> list[str]:
        signals = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if not isinstance(status, dict):
                continue
            waiting = status.get("state", {}).get("waiting") or {}
            reason = self._message(waiting.get("reason"))
            message = self._message(waiting.get("message"))
            text = f"{reason} {message}".lower()
            if self._is_gpu_text(text) and any(
                marker in text for marker in self.GPU_FAILURE_MARKERS
            ):
                container_name = self._message(status.get("name")) or "<unknown>"
                signals.append(
                    f"Container {container_name} waiting reason={reason or '<unknown>'}"
                )
        return signals

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        phase = get_pod_phase(pod)
        if phase not in {"Pending", "Running", "Unknown"}:
            return None

        gpu_requests = self._gpu_extended_resource_requests(pod)
        gpu_records = self._gpu_dra_records(pod, context)
        if not gpu_requests and not gpu_records:
            return None

        resource_names = set(gpu_requests)
        dra_names = self._dra_name_set(gpu_records)
        matching_events = self._matching_gpu_events(
            pod,
            events,
            context,
            resource_names=resource_names,
            dra_names=dra_names,
        )

        capacity_signals = self._node_gpu_capacity_signals(context, gpu_requests)
        dra_signals = self._dra_gpu_failure_signals(context, gpu_records)
        waiting_signals = self._pod_has_gpu_waiting_state(pod)

        # Plain absence of an extended GPU resource is handled by
        # ExtendedResourceUnavailable. Capacity signals here only enrich stronger
        # GPU allocation/admission/DRA evidence.
        if matching_events or dra_signals or waiting_signals:
            return {
                "gpu_requests": gpu_requests,
                "gpu_records": gpu_records,
                "events": matching_events,
                "capacity_signals": capacity_signals,
                "dra_signals": dra_signals,
                "waiting_signals": waiting_signals,
            }

        return None

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, events, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, events, context)
        if candidate is None:
            raise ValueError("GPUDeviceAllocationFailed explain() called without match")

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        namespace = self._namespace(pod)
        gpu_requests = candidate.get("gpu_requests", {}) or {}
        gpu_records = candidate.get("gpu_records", []) or []
        matching_events = candidate.get("events", []) or []
        capacity_signals = candidate.get("capacity_signals", []) or []
        dra_signals = candidate.get("dra_signals", []) or []
        waiting_signals = candidate.get("waiting_signals", []) or []

        resource_display = ", ".join(
            f"{name}={value}" for name, value in gpu_requests.items()
        )
        device_classes = list(
            dict.fromkeys(
                str(device_class)
                for record in gpu_records
                for device_class in record.get("device_class_names", []) or []
            )
        )
        class_display = ", ".join(device_classes)
        requested_display = (
            ", ".join(item for item in (resource_display, class_display) if item)
            or "<unknown>"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REQUESTS_GPU_DEVICE",
                    message=f"Pod requests GPU device capacity: {requested_display}",
                    role="workload_context",
                ),
                Cause(
                    code="GPU_DEVICE_ALLOCATION_FAILED",
                    message="Kubernetes could not allocate a matching GPU device for the Pod",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_BLOCKED_ON_GPU_CAPACITY",
                    message="Pod cannot schedule or start until GPU device allocation succeeds",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
            f"GPU request(s)={requested_display}",
        ]
        evidence.extend(capacity_signals)
        evidence.extend(dra_signals)
        evidence.extend(waiting_signals)

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]
        if event_messages:
            evidence.append(
                f"GPU allocation failure event observed {len(event_messages)} time(s)"
            )
            evidence.extend(event_messages[:2])

        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                f"Requests GPU device capacity: {requested_display}",
                *event_messages[:3],
                *waiting_signals,
            ]
        }

        for resource in gpu_requests:
            object_evidence[f"resource:{resource}"] = [
                signal
                for signal in capacity_signals
                if resource.lower() in signal.lower()
            ] or ["Requested by Pod"]

        for record in gpu_records:
            ref = record.get("ref") or {}
            claim_name = ref.get("claim_name")
            if isinstance(claim_name, str) and claim_name:
                object_evidence.setdefault(
                    f"resourceclaim:{namespace}/{claim_name}",
                    [],
                ).extend(
                    dra_signals or ["GPU DRA ResourceClaim participates in failure"]
                )

            for device_class_name in record.get("device_class_names", []) or []:
                object_evidence.setdefault(
                    f"deviceclass:{device_class_name}",
                    [],
                ).append("GPU DeviceClass referenced by failing allocation")

        confidence = 0.88
        if event_messages and (capacity_signals or dra_signals or waiting_signals):
            confidence = 0.97
        elif capacity_signals or dra_signals:
            confidence = 0.94
        elif event_messages:
            confidence = 0.92

        return {
            "rule": self.name,
            "root_cause": "GPU device allocation failed for the Pod",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "No node has enough allocatable GPU devices for the Pod request",
                "All matching GPUs are already allocated to other workloads",
                "The GPU DeviceClass selectors, constraints, MIG profile, or taints exclude available devices",
                "A DRA ResourceClaim hit a binding failure condition or no matching ResourceSlice",
                "GPU topology or NUMA constraints prevented kubelet admission after scheduling",
                "GPU resource name does not match what the device plugin or DRA driver advertises",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get nodes -o json | jq '.items[].status.allocatable'",
                "kubectl describe node <gpu-node>",
                "kubectl get resourceslice -A",
                "kubectl get deviceclass",
                f"kubectl get resourceclaim -n {namespace}",
                "Check GPU device plugin or DRA driver logs for allocation errors",
                "Verify GPU/MIG profiles, device taints, node labels, and topology policies",
            ],
        }
