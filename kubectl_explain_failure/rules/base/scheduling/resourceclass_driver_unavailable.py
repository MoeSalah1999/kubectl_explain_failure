from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class ResourceClassDriverUnavailableRule(FailureRule):
    """
    Detects Pods blocked because a Dynamic Resource Allocation ResourceClass
    points at a driver that is not currently usable.

    Real-world behavior:
    - Older DRA APIs used ResourceClaim.spec.resourceClassName and
      ResourceClass.driverName.
    - Pods can reference direct ResourceClaims or ResourceClaimTemplates; the
      scheduler records generated claim names in pod.status.resourceClaimStatuses.
    - Driver unavailability normally surfaces as FailedScheduling events,
      ResourceClaim conditions, absent ResourceSlices for the driver, or unhealthy
      driver controller/node plugin workloads.
    - A missing ResourceClass or ResourceClaim is a different root cause, so this
      rule avoids matching "not found" signals.
    """

    name = "ResourceClassDriverUnavailable"
    category = "Scheduling"
    priority = 91
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
            "resourceslice",
            "pod",
            "daemonset",
            "deployment",
        ],
    }

    CACHE_KEY = "_resourceclass_driver_unavailable_candidate"
    WINDOW_MINUTES = 60

    DRA_MARKERS = (
        "dynamic resource",
        "resourceclaim",
        "resource claim",
        "resourceclass",
        "resource class",
        "resource.k8s.io",
        "dra",
    )
    DRIVER_MARKERS = (
        "driver",
        "plugin",
        "resource driver",
        "dra driver",
    )
    UNAVAILABLE_MARKERS = (
        "unavailable",
        "not available",
        "not ready",
        "isn't ready",
        "is not ready",
        "unhealthy",
        "no healthy",
        "not registered",
        "no driver",
        "driver missing",
        "driver not found",
        "not found in driver",
        "no resourceslices",
        "no resource slices",
        "no resourceslice",
        "no matching resourceslices",
        "no matching resource slices",
        "no suitable resourceslices",
        "resource slices are not available",
        "cannot allocate",
        "failed to allocate",
        "allocation failed",
        "allocation error",
        "allocation timeout",
        "timed out waiting for driver",
    )
    NOT_FOUND_MARKERS = (
        "resourceclass not found",
        "resource class not found",
        "no resourceclass",
        "no resource class",
        "resourceclaim not found",
        "resource claim not found",
        "does not exist",
    )
    UNHEALTHY_POD_REASONS = (
        "crashloopbackoff",
        "imagepullbackoff",
        "errimagepull",
        "createcontainerconfigerror",
        "runcontainererror",
        "containercreating",
    )

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _namespace(self, obj: dict[str, Any]) -> str:
        return self._message(obj.get("metadata", {}).get("namespace")) or "default"

    def _object_list(
        self, context: dict[str, Any], *names: str
    ) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        results: list[dict[str, Any]] = []

        for name in names:
            raw = objects.get(name)
            if isinstance(raw, dict):
                if "metadata" in raw or "spec" in raw or "status" in raw:
                    results.append(raw)
                else:
                    results.extend(obj for obj in raw.values() if isinstance(obj, dict))
            elif isinstance(raw, list):
                results.extend(obj for obj in raw if isinstance(obj, dict))

        return results

    def _claim_statuses(self, pod: dict[str, Any]) -> dict[str, str]:
        statuses = {}
        for entry in pod.get("status", {}).get("resourceClaimStatuses", []) or []:
            if not isinstance(entry, dict):
                continue
            logical_name = entry.get("name")
            claim_name = entry.get("resourceClaimName")
            if isinstance(logical_name, str) and isinstance(claim_name, str):
                statuses[logical_name] = claim_name
        return statuses

    def _pod_claim_refs(self, pod: dict[str, Any]) -> list[dict[str, str | None]]:
        claim_statuses = self._claim_statuses(pod)
        refs = []

        for entry in pod.get("spec", {}).get("resourceClaims", []) or []:
            if not isinstance(entry, dict):
                continue

            logical_name = entry.get("name")
            if not isinstance(logical_name, str) or not logical_name.strip():
                continue

            direct_name = entry.get("resourceClaimName")
            template_name = entry.get("resourceClaimTemplateName")
            refs.append(
                {
                    "logical_name": logical_name.strip(),
                    "claim_name": (
                        direct_name.strip()
                        if isinstance(direct_name, str) and direct_name.strip()
                        else claim_statuses.get(logical_name)
                    ),
                    "template_name": (
                        template_name.strip()
                        if isinstance(template_name, str) and template_name.strip()
                        else None
                    ),
                    "source": "direct" if direct_name else "template",
                }
            )

        return refs

    def _find_by_name(
        self,
        objects: list[dict[str, Any]],
        *,
        name: str,
        namespace: str | None = None,
        namespaced: bool = True,
    ) -> dict[str, Any] | None:
        for obj in objects:
            metadata = obj.get("metadata", {}) or {}
            if metadata.get("name") != name:
                continue
            if namespaced and namespace is not None:
                obj_namespace = metadata.get("namespace", namespace)
                if obj_namespace != namespace:
                    continue
            return obj
        return None

    def _claim_class_name(self, claim: dict[str, Any]) -> str | None:
        spec = claim.get("spec", {}) or {}
        resource_class_name = spec.get("resourceClassName")
        if isinstance(resource_class_name, str) and resource_class_name.strip():
            return resource_class_name.strip()

        class_name = spec.get("className")
        if isinstance(class_name, str) and class_name.strip():
            return class_name.strip()

        return None

    def _template_class_name(self, template: dict[str, Any]) -> str | None:
        spec = template.get("spec", {}) or {}
        claim_spec = spec.get("spec", spec)
        if not isinstance(claim_spec, dict):
            return None
        return self._claim_class_name({"spec": claim_spec})

    def _resourceclass_driver(self, resource_class: dict[str, Any]) -> str | None:
        spec = resource_class.get("spec", {}) or {}
        for key in ("driverName", "driver"):
            value = spec.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _resourceclass_unavailable_conditions(
        self,
        resource_class: dict[str, Any],
    ) -> list[str]:
        messages = []
        for condition in resource_class.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue

            cond_type = self._message(condition.get("type"))
            status = self._message(condition.get("status")).lower()
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            combined = f"{cond_type} {reason} {message}".lower()

            if status == "true" and any(
                marker in combined
                for marker in ("unavailable", "notready", "degraded", "failing")
            ):
                messages.append(
                    f"ResourceClass condition {cond_type}=True reason={reason or '<unknown>'}"
                )
            elif cond_type.lower() in ("ready", "available") and status in (
                "false",
                "unknown",
            ):
                messages.append(
                    f"ResourceClass condition {cond_type}={condition.get('status')} reason={reason or '<unknown>'}"
                )

        return messages

    def _claim_driver_failure_conditions(self, claim: dict[str, Any]) -> list[str]:
        messages = []
        for condition in claim.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue

            status = self._message(condition.get("status")).lower()
            if status not in ("true", "false", "unknown"):
                continue

            cond_type = self._message(condition.get("type"))
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            combined = f"{cond_type} {reason} {message}".lower()

            if not any(marker in combined for marker in self.DRIVER_MARKERS):
                continue
            if not any(marker in combined for marker in self.UNAVAILABLE_MARKERS):
                continue

            messages.append(
                f"ResourceClaim condition {cond_type}={condition.get('status')} reason={reason or '<unknown>'}"
            )

        return messages

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

    def _event_mentions_pod(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}
        if isinstance(involved, dict):
            namespace = self._message(involved.get("namespace")) or pod_namespace
            if namespace != pod_namespace:
                return False
            if self._message(involved.get("kind")).lower() == "pod":
                return self._message(involved.get("name")) == pod_name

        message = self._message(event.get("message")).lower()
        return bool(pod_name and pod_name.lower() in message)

    def _looks_driver_unavailable_event(
        self,
        event: dict[str, Any],
        *,
        names: set[str],
    ) -> bool:
        message = self._message(event.get("message"))
        combined = f"{event.get('reason') or ''} {message}".lower()

        if any(marker in combined for marker in self.NOT_FOUND_MARKERS):
            return False

        has_dra_context = any(marker in combined for marker in self.DRA_MARKERS)
        has_driver_context = any(marker in combined for marker in self.DRIVER_MARKERS)
        has_unavailable_context = any(
            marker in combined for marker in self.UNAVAILABLE_MARKERS
        )

        if not (has_unavailable_context and (has_dra_context or has_driver_context)):
            return False

        if not names:
            return True

        return any(name.lower() in combined for name in names if name)

    def _matching_events(
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
            if not self._looks_driver_unavailable_event(event, names=names):
                continue
            if not self._event_mentions_pod(
                event, pod_name=pod_name, pod_namespace=pod_namespace
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            matches.append(event)

        return matches

    def _resourceslice_driver_names(
        self,
        context: dict[str, Any],
    ) -> set[str]:
        drivers = set()
        for slice_obj in self._object_list(context, "resourceslice", "resourceslices"):
            spec = slice_obj.get("spec", {}) or {}
            driver = spec.get("driver")
            if isinstance(driver, str) and driver.strip():
                drivers.add(driver.strip())
        return drivers

    def _driver_workloads(
        self,
        context: dict[str, Any],
        *,
        driver: str,
    ) -> list[dict[str, Any]]:
        driver_lower = driver.lower()
        workloads = []

        for obj in self._object_list(
            context,
            "pod",
            "pods",
            "daemonset",
            "daemonsets",
            "deployment",
            "deployments",
        ):
            metadata = obj.get("metadata", {}) or {}
            labels = metadata.get("labels", {}) or {}
            name = self._message(metadata.get("name")).lower()
            label_text = " ".join(
                f"{key}={value}" for key, value in labels.items()
            ).lower()
            spec_text = self._message(obj.get("spec", {}).get("driverName")).lower()
            if (
                driver_lower in name
                or driver_lower in label_text
                or driver_lower in spec_text
            ):
                workloads.append(obj)

        return workloads

    def _workload_unavailable_evidence(
        self,
        workloads: list[dict[str, Any]],
    ) -> list[str]:
        evidence = []

        for obj in workloads:
            kind = self._message(obj.get("kind")).lower()
            metadata = obj.get("metadata", {}) or {}
            name = self._message(metadata.get("name")) or "<unknown>"

            if kind == "pod" or "containerStatuses" in obj.get("status", {}):
                phase = self._message(obj.get("status", {}).get("phase"))
                ready = True
                reasons = []
                for status in obj.get("status", {}).get("containerStatuses", []) or []:
                    if not isinstance(status, dict):
                        continue
                    ready = ready and bool(status.get("ready"))
                    waiting = status.get("state", {}).get("waiting", {}) or {}
                    reason = self._message(waiting.get("reason"))
                    if reason:
                        reasons.append(reason)

                if (
                    phase in ("Failed", "Unknown")
                    or not ready
                    or any(
                        reason.lower() in self.UNHEALTHY_POD_REASONS
                        for reason in reasons
                    )
                ):
                    reason_display = f" reason={', '.join(reasons)}" if reasons else ""
                    evidence.append(
                        f"DRA driver pod {name} phase={phase or '<unknown>'} ready={ready}{reason_display}"
                    )
                continue

            status = obj.get("status", {}) or {}
            desired = status.get("desiredNumberScheduled") or status.get("replicas")
            available = (
                status.get("numberAvailable")
                if "numberAvailable" in status
                else status.get("availableReplicas")
            )
            unavailable = status.get("numberUnavailable") or status.get(
                "unavailableReplicas"
            )
            if unavailable or (desired is not None and available in (None, 0)):
                evidence.append(
                    f"DRA driver {kind or 'workload'} {name} desired={desired} available={available or 0}"
                )

        return evidence

    def _class_records(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        namespace = self._namespace(pod)
        claims = self._object_list(context, "resourceclaim", "resourceclaims")
        templates = self._object_list(
            context, "resourceclaimtemplate", "resourceclaimtemplates"
        )
        resource_classes = self._object_list(
            context, "resourceclass", "resourceclasses"
        )
        refs = self._pod_claim_refs(pod)
        records = []

        for ref in refs:
            class_name = None
            claim = None
            claim_name = ref.get("claim_name")
            if isinstance(claim_name, str) and claim_name:
                claim = self._find_by_name(
                    claims, name=claim_name, namespace=namespace, namespaced=True
                )
                if claim is not None:
                    class_name = self._claim_class_name(claim)

            template = None
            template_name = ref.get("template_name")
            if class_name is None and isinstance(template_name, str) and template_name:
                template = self._find_by_name(
                    templates, name=template_name, namespace=namespace, namespaced=True
                )
                if template is not None:
                    class_name = self._template_class_name(template)

            resource_class = None
            driver = None
            if class_name:
                resource_class = self._find_by_name(
                    resource_classes,
                    name=class_name,
                    namespace=None,
                    namespaced=False,
                )
                if resource_class is not None:
                    driver = self._resourceclass_driver(resource_class)

            records.append(
                {
                    "ref": ref,
                    "claim": claim,
                    "template": template,
                    "class_name": class_name,
                    "resource_class": resource_class,
                    "driver": driver,
                }
            )

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
            ref = record.get("ref") or {}
            for key in ("logical_name", "claim_name", "template_name"):
                value = ref.get(key)
                if isinstance(value, str) and value:
                    names.add(value)

        matching_events = self._matching_events(pod, events, context, names=names)
        slice_drivers = self._resourceslice_driver_names(context)
        slice_graph_present = bool(
            context.get("objects", {}).get("resourceslice")
            or context.get("objects", {}).get("resourceslices")
        )

        unavailable_records = []
        for record in records:
            class_name = record.get("class_name")
            resource_class = record.get("resource_class")
            driver = record.get("driver")
            claim = record.get("claim")

            if not class_name:
                continue
            if resource_class is None:
                continue

            signals = []
            if isinstance(resource_class, dict):
                signals.extend(
                    self._resourceclass_unavailable_conditions(resource_class)
                )
            if isinstance(claim, dict):
                signals.extend(self._claim_driver_failure_conditions(claim))

            if driver and slice_graph_present and driver not in slice_drivers:
                signals.append(
                    f"No ResourceSlice objects are published for driver {driver}"
                )

            workloads = self._driver_workloads(context, driver=driver) if driver else []
            workload_evidence = self._workload_unavailable_evidence(workloads)
            signals.extend(workload_evidence)

            event_messages = [
                self._message(event.get("message"))
                for event in matching_events
                if self._message(event.get("message"))
            ]
            if event_messages and (
                not driver
                or any(driver.lower() in msg.lower() for msg in event_messages)
                or any(str(class_name).lower() in msg.lower() for msg in event_messages)
            ):
                signals.append(
                    f"Driver unavailable scheduling event observed {len(event_messages)} time(s)"
                )

            if signals:
                unavailable_records.append(
                    {
                        **record,
                        "signals": list(dict.fromkeys(signals)),
                        "workloads": workloads,
                    }
                )

        if unavailable_records:
            return {
                "records": records,
                "unavailable_records": unavailable_records,
                "events": matching_events,
                "slice_graph_present": slice_graph_present,
            }

        if matching_events:
            return {
                "records": records,
                "unavailable_records": [],
                "events": matching_events,
                "slice_graph_present": slice_graph_present,
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
                "ResourceClassDriverUnavailable explain() called without match"
            )

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        namespace = self._namespace(pod)
        unavailable_records = candidate.get("unavailable_records", [])
        records = unavailable_records or candidate.get("records", [])
        matching_events = candidate.get("events", [])

        class_names = list(
            dict.fromkeys(
                str(record.get("class_name"))
                for record in records
                if record.get("class_name")
            )
        )
        drivers = list(
            dict.fromkeys(
                str(record.get("driver")) for record in records if record.get("driver")
            )
        )
        ref_names = list(
            dict.fromkeys(
                str((record.get("ref") or {}).get("logical_name"))
                for record in records
                if (record.get("ref") or {}).get("logical_name")
            )
        )
        driver_display = ", ".join(drivers) or "<unknown>"
        class_display = ", ".join(class_names) or "<unknown>"

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REFERENCES_RESOURCECLASS",
                    message=f"Pod references DRA ResourceClass(es): {class_display}",
                    role="workload_context",
                ),
                Cause(
                    code="RESOURCECLASS_DRIVER_UNAVAILABLE",
                    message=f"ResourceClass driver is unavailable: {driver_display}",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_WAITING_FOR_DRA_DRIVER",
                    message="Pod cannot be scheduled until the dynamic resource driver can allocate the claim",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
            f"Pod.spec.resourceClaims={', '.join(ref_names)}",
            f"ResourceClass={class_display}",
            f"ResourceClass driver={driver_display}",
        ]
        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                f"References DRA resource claim entry/entries: {', '.join(ref_names)}",
                f"Resolved ResourceClass(es): {class_display}",
            ]
        }

        for record in unavailable_records:
            class_name = str(record.get("class_name") or "<unknown>")
            driver = str(record.get("driver") or "<unknown>")
            object_evidence.setdefault(f"resourceclass:{class_name}", []).append(
                f"driverName={driver}"
            )
            for signal in record.get("signals", []):
                evidence.append(signal)
                object_evidence[f"resourceclass:{class_name}"].append(signal)

            claim = record.get("claim")
            if isinstance(claim, dict):
                claim_name = self._message(claim.get("metadata", {}).get("name"))
                if claim_name:
                    object_evidence.setdefault(
                        f"resourceclaim:{namespace}/{claim_name}", []
                    ).append(f"Uses ResourceClass {class_name}")

            for workload in record.get("workloads", []):
                metadata = workload.get("metadata", {}) or {}
                name = self._message(metadata.get("name"))
                workload_namespace = self._message(metadata.get("namespace"))
                kind = self._message(workload.get("kind")).lower() or "workload"
                if name:
                    key = (
                        f"{kind}:{workload_namespace}/{name}"
                        if workload_namespace
                        else f"{kind}:{name}"
                    )
                    object_evidence.setdefault(key, []).append(
                        f"Matches DRA driver {driver}"
                    )

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]
        if event_messages:
            evidence.append(
                f"Driver unavailable event observed {len(event_messages)} time(s)"
            )
            evidence.extend(event_messages[:2])
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(event_messages[:3])

        confidence = 0.86
        if unavailable_records and event_messages:
            confidence = 0.96
        elif unavailable_records:
            confidence = 0.92
        elif event_messages:
            confidence = 0.9

        return {
            "rule": self.name,
            "root_cause": "Dynamic Resource Allocation driver for the ResourceClass is unavailable",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "The DRA driver controller or node plugin is not running or not ready",
                "The ResourceClass references the wrong driverName",
                "The driver is installed but has not published ResourceSlices",
                "The driver lacks RBAC permissions to watch or update resource.k8s.io objects",
                "The driver cannot allocate devices because its backend is unhealthy or unreachable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl get resourceclaim -n {namespace}",
                f"kubectl describe resourceclass {class_names[0] if class_names else '<class-name>'}",
                "kubectl get resourceslice -A",
                "kubectl get pods -A -l app.kubernetes.io/component in (dra-driver,device-plugin)",
                f"Check logs for the DRA driver {driver_display}",
            ],
        }
