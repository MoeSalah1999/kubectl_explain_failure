from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base.scheduling.resourceclass_driver_unavailable import (
    ResourceClassDriverUnavailableRule,
)


class DynamicResourceAllocationFailedRule(ResourceClassDriverUnavailableRule):
    """
    Detects hard Dynamic Resource Allocation failures for Pods.

    Real-world behavior:
    - DRA allocation is performed against ResourceClaims referenced directly by a
      Pod or generated from ResourceClaimTemplates.
    - Older clusters used ResourceClass; current resource.k8s.io APIs primarily
      allocate requests against DeviceClasses and ResourceSlices.
    - A claim can be unallocated because work is still pending. This rule only
      matches when Kubernetes or the driver reports an actual allocation or
      binding failure.
    - Device binding failure conditions can abort scheduler binding after
      allocation; that is still a DRA scheduling failure for the Pod.
    """

    name = "DynamicResourceAllocationFailed"
    category = "Scheduling"
    priority = 90
    deterministic = False
    phases = ["Pending", "Unknown"]
    blocks = [
        "ResourceClaimPending",
        "FailedScheduling",
        "PendingUnschedulable",
        "InsufficientResources",
        "ExtendedResourceUnavailable",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "UnschedulableTaint",
        "ClusterAutoscalerScaleUpFailed",
    ]

    requires = {
        "pod": True,
        "optional_objects": [
            "resourceclaim",
            "resourceclaimtemplate",
            "resourceclass",
            "deviceclass",
            "resourceslice",
        ],
    }

    CACHE_KEY = "_dynamic_resource_allocation_failed_candidate"

    FAILURE_CONDITION_TYPES = (
        "allocationfailed",
        "allocationfailure",
        "resourceallocationfailed",
        "deviceallocationfailed",
        "bindingfailed",
        "bindingfailure",
        "devicebindingfailed",
        "failed",
    )
    FAILURE_REASONS = (
        "allocationfailed",
        "allocationfailure",
        "bindingfailed",
        "bindingfailure",
        "devicebindingfailed",
        "resourceexhausted",
        "capacityexhausted",
        "unsatisfiable",
        "unsuitable",
        "noavailabledevices",
        "nomatchingdevices",
        "nomatchingresourceslices",
        "claimallocationfailed",
    )
    FAILURE_MARKERS = (
        "failed to allocate",
        "allocation failed",
        "allocation failure",
        "could not allocate",
        "cannot allocate",
        "unable to allocate",
        "failed allocation",
        "claim allocation failed",
        "resource allocation failed",
        "device allocation failed",
        "failed to bind dynamic resource",
        "binding failed",
        "device binding failed",
        "binding failure condition",
        "binding failure",
        "timed out waiting for binding",
        "timed out waiting for device",
        "no devices available",
        "no available devices",
        "no matching devices",
        "no suitable devices",
        "no device satisfies",
        "no resourceslice matches",
        "no resource slice matches",
        "not enough devices",
        "resource pool exhausted",
        "capacity exhausted",
        "device taint",
        "tainted device",
        "not tolerated",
        "cel expression",
        "selector did not match",
        "constraint did not match",
        "admin access",
    )
    PENDING_ONLY_MARKERS = (
        "waiting for allocation",
        "allocation pending",
        "pending allocation",
        "not yet allocated",
        "not allocated yet",
        "waiting for resourceclaim",
        "waiting for resource claim",
    )

    def _normalized(self, value: Any) -> str:
        return "".join(ch for ch in self._message(value).lower() if ch.isalnum())

    def _claim_device_class_names(self, claim: dict[str, Any]) -> list[str]:
        spec = claim.get("spec", {}) or {}
        names = []

        devices = spec.get("devices")
        if isinstance(devices, dict):
            for request in devices.get("requests", []) or []:
                if not isinstance(request, dict):
                    continue

                class_name = request.get("deviceClassName")
                if isinstance(class_name, str) and class_name.strip():
                    names.append(class_name.strip())

                first_available = request.get("firstAvailable")
                if isinstance(first_available, list):
                    for subrequest in first_available:
                        if not isinstance(subrequest, dict):
                            continue
                        class_name = subrequest.get("deviceClassName")
                        if isinstance(class_name, str) and class_name.strip():
                            names.append(class_name.strip())

        return list(dict.fromkeys(names))

    def _template_device_class_names(self, template: dict[str, Any]) -> list[str]:
        spec = template.get("spec", {}) or {}
        claim_spec = spec.get("spec", spec)
        if not isinstance(claim_spec, dict):
            return []
        return self._claim_device_class_names({"spec": claim_spec})

    def _deviceclass_names_from_records(
        self,
        records: list[dict[str, Any]],
    ) -> list[str]:
        names = []
        for record in records:
            claim = record.get("claim")
            template = record.get("template")
            if isinstance(claim, dict):
                names.extend(self._claim_device_class_names(claim))
            if isinstance(template, dict):
                names.extend(self._template_device_class_names(template))
        return list(dict.fromkeys(names))

    def _claim_failure_conditions(self, claim: dict[str, Any]) -> list[str]:
        messages = []
        for condition in claim.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue

            status = self._message(condition.get("status")).lower()
            if status != "true":
                continue

            cond_type = self._message(condition.get("type"))
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            combined = f"{cond_type} {reason} {message}".lower()
            normalized_type = self._normalized(cond_type)
            normalized_reason = self._normalized(reason)

            if (
                normalized_type in self.FAILURE_CONDITION_TYPES
                or normalized_reason in self.FAILURE_REASONS
                or any(marker in combined for marker in self.FAILURE_MARKERS)
            ):
                messages.append(
                    f"ResourceClaim condition {cond_type}=True reason={reason or '<unknown>'}"
                )

        return messages

    def _claim_allocation_failed(self, claim: dict[str, Any]) -> list[str]:
        evidence = self._claim_failure_conditions(claim)
        status = claim.get("status", {}) or {}

        allocation = status.get("allocation")
        if evidence and not (isinstance(allocation, dict) and allocation):
            evidence.append("ResourceClaim has no successful status.allocation")

        allocation_status = status.get("allocationStatus")
        if isinstance(allocation_status, dict):
            result = self._message(allocation_status.get("result")).lower()
            error = self._message(allocation_status.get("error"))
            if result in ("failed", "failure", "error") or error:
                evidence.append(
                    f"ResourceClaim allocationStatus reports {result or 'error'}"
                )

        return list(dict.fromkeys(evidence))

    def _event_mentions_known_name(
        self,
        message: str,
        names: set[str],
    ) -> bool:
        if not names:
            return True
        lowered = message.lower()
        return any(name.lower() in lowered for name in names if name)

    def _looks_allocation_failed_event(
        self,
        event: dict[str, Any],
        *,
        names: set[str],
    ) -> bool:
        message = self._message(event.get("message"))
        combined = f"{event.get('reason') or ''} {message}".lower()

        if any(marker in combined for marker in self.NOT_FOUND_MARKERS):
            return False

        if any(marker in combined for marker in self.PENDING_ONLY_MARKERS) and not any(
            marker in combined for marker in self.FAILURE_MARKERS
        ):
            return False

        has_dra_context = any(marker in combined for marker in self.DRA_MARKERS) or any(
            marker in combined
            for marker in ("deviceclass", "device class", "resourceslice")
        )
        has_failure_context = any(marker in combined for marker in self.FAILURE_MARKERS)

        if not (has_dra_context and has_failure_context):
            return False

        return self._event_mentions_known_name(message, names)

    def _matching_allocation_failed_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
        *,
        names: set[str],
    ) -> list[dict[str, Any]]:
        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        pod_namespace = self._namespace(pod)
        matches = []

        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue
            if not self._looks_allocation_failed_event(event, names=names):
                continue
            if not self._event_mentions_pod(
                event,
                pod_name=pod_name,
                pod_namespace=pod_namespace,
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            matches.append(event)

        return matches

    def _resource_slice_count_for_device_classes(
        self,
        context: dict[str, Any],
        device_class_names: list[str],
    ) -> dict[str, int]:
        counts = {name: 0 for name in device_class_names}
        if not counts:
            return counts

        for slice_obj in self._object_list(context, "resourceslice", "resourceslices"):
            spec = slice_obj.get("spec", {}) or {}
            devices = spec.get("devices", []) or []
            slice_text = str(spec).lower()
            for device_class_name in counts:
                if device_class_name.lower() in slice_text:
                    counts[device_class_name] += 1
                    continue

                for device in devices:
                    if not isinstance(device, dict):
                        continue
                    attributes = str(device.get("attributes", {})).lower()
                    if device_class_name.lower() in attributes:
                        counts[device_class_name] += 1
                        break

        return counts

    def _class_records(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        records = super()._class_records(pod, context)
        device_classes = self._object_list(context, "deviceclass", "deviceclasses")

        for record in records:
            class_names = []
            claim = record.get("claim")
            template = record.get("template")
            if isinstance(claim, dict):
                class_names.extend(self._claim_device_class_names(claim))
            if isinstance(template, dict):
                class_names.extend(self._template_device_class_names(template))

            matched_device_classes = []
            for class_name in dict.fromkeys(class_names):
                device_class = self._find_by_name(
                    device_classes,
                    name=class_name,
                    namespace=None,
                    namespaced=False,
                )
                if device_class is not None:
                    matched_device_classes.append(device_class)

            record["device_class_names"] = list(dict.fromkeys(class_names))
            record["device_classes"] = matched_device_classes

        return records

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if pod.get("spec", {}).get("schedulingGates"):
            return None
        if get_pod_phase(pod) not in {"Pending", "Unknown"}:
            return None

        records = self._class_records(pod, context)
        if not records:
            return None

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

        matching_events = self._matching_allocation_failed_events(
            pod, events, context, names=names
        )
        device_class_names = self._deviceclass_names_from_records(records)
        resource_slice_counts = self._resource_slice_count_for_device_classes(
            context, device_class_names
        )

        failed_records = []
        for record in records:
            claim = record.get("claim")
            signals = []
            if isinstance(claim, dict):
                signals.extend(self._claim_allocation_failed(claim))

            for device_class_name in record.get("device_class_names", []) or []:
                if (
                    resource_slice_counts
                    and resource_slice_counts.get(device_class_name) == 0
                ):
                    signals.append(
                        f"No ResourceSlice advertises devices for DeviceClass {device_class_name}"
                    )

            event_messages = [
                self._message(event.get("message"))
                for event in matching_events
                if self._message(event.get("message"))
            ]
            if event_messages:
                signals.append(
                    f"DRA allocation failure event observed {len(event_messages)} time(s)"
                )

            if signals:
                failed_records.append(
                    {
                        **record,
                        "signals": list(dict.fromkeys(signals)),
                    }
                )

        if failed_records:
            return {
                "records": records,
                "failed_records": failed_records,
                "events": matching_events,
                "device_class_names": device_class_names,
                "resource_slice_counts": resource_slice_counts,
            }

        if matching_events:
            return {
                "records": records,
                "failed_records": [],
                "events": matching_events,
                "device_class_names": device_class_names,
                "resource_slice_counts": resource_slice_counts,
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
            raise ValueError(
                "DynamicResourceAllocationFailed explain() called without match"
            )

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        namespace = self._namespace(pod)
        failed_records = candidate.get("failed_records", [])
        records = failed_records or candidate.get("records", [])
        matching_events = candidate.get("events", [])

        ref_names = list(
            dict.fromkeys(
                str((record.get("ref") or {}).get("logical_name"))
                for record in records
                if (record.get("ref") or {}).get("logical_name")
            )
        )
        claim_names = list(
            dict.fromkeys(
                str((record.get("ref") or {}).get("claim_name"))
                for record in records
                if (record.get("ref") or {}).get("claim_name")
            )
        )
        resource_classes = list(
            dict.fromkeys(
                str(record.get("class_name"))
                for record in records
                if record.get("class_name")
            )
        )
        device_classes = list(
            dict.fromkeys(
                str(device_class)
                for record in records
                for device_class in record.get("device_class_names", []) or []
            )
        )

        class_display = ", ".join(device_classes or resource_classes) or "<unknown>"
        claim_display = ", ".join(claim_names or ref_names) or "<unknown>"

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REFERENCES_DYNAMIC_RESOURCE",
                    message=f"Pod references Dynamic Resource Allocation claim(s): {claim_display}",
                    role="workload_context",
                ),
                Cause(
                    code="DYNAMIC_RESOURCE_ALLOCATION_FAILED",
                    message=f"DRA could not allocate or bind requested device class/resource class: {class_display}",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SCHEDULING_BLOCKED_BY_DRA",
                    message="Pod remains unscheduled because its dynamic resource claim cannot be satisfied",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
            f"Pod.spec.resourceClaims={', '.join(ref_names)}",
            f"DRA class reference(s)={class_display}",
        ]
        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                f"References DRA claim entry/entries: {', '.join(ref_names)}",
                f"Resolved DRA class reference(s): {class_display}",
            ]
        }

        for record in failed_records:
            ref = record.get("ref") or {}
            claim_name = ref.get("claim_name")
            if isinstance(claim_name, str) and claim_name:
                claim_key = f"resourceclaim:{namespace}/{claim_name}"
                object_evidence.setdefault(claim_key, [])
                for signal in record.get("signals", []):
                    evidence.append(signal)
                    object_evidence[claim_key].append(signal)

            for device_class_name in record.get("device_class_names", []) or []:
                object_evidence.setdefault(
                    f"deviceclass:{device_class_name}", []
                ).append("Referenced by failing ResourceClaim request")

            resource_class_name = record.get("class_name")
            if isinstance(resource_class_name, str) and resource_class_name:
                object_evidence.setdefault(
                    f"resourceclass:{resource_class_name}", []
                ).append("Referenced by failing ResourceClaim")

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]
        if event_messages:
            evidence.append(
                f"DRA allocation failure event observed {len(event_messages)} time(s)"
            )
            evidence.extend(event_messages[:2])
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(event_messages[:3])

        confidence = 0.88
        if failed_records and event_messages:
            confidence = 0.97
        elif failed_records:
            confidence = 0.94
        elif event_messages:
            confidence = 0.91

        return {
            "rule": self.name,
            "root_cause": "Dynamic Resource Allocation failed for the Pod",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "No ResourceSlice device satisfies the ResourceClaim's DeviceClass selectors or constraints",
                "The requested device pool is exhausted or all matching devices are already allocated",
                "A device taint or binding failure condition prevented the scheduler from binding the Pod",
                "The DRA driver rejected the claim due to invalid parameters or backend allocation failure",
                "DRA feature gates, scheduler configuration, or resource.k8s.io RBAC are inconsistent across components",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl get resourceclaim -n {namespace}",
                f"kubectl describe resourceclaim {claim_names[0] if claim_names else '<claim-name>'} -n {namespace}",
                "kubectl get deviceclass",
                "kubectl get resourceslice -A",
                "Inspect ResourceClaim.status.conditions, status.allocation, and any device binding failure conditions",
                "Check kube-scheduler logs and the DRA driver logs for allocation errors",
            ],
        }
