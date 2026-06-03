from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class ResourceClaimPendingRule(FailureRule):
    """
    Detects Pods blocked on Dynamic Resource Allocation ResourceClaims.

    Real-world behavior:
    - Pods can reference ResourceClaims directly or through a
      ResourceClaimTemplate; generated claim names are recorded in
      status.resourceClaimStatuses
    - ResourceClaim.status.allocation is set when allocation succeeds
    - status.reservedFor records which Pods may use the claim; a Pod whose claim
      is not allocated or not reserved for it cannot start
    - a direct ResourceClaim that does not exist is a not-found problem, not a
      pending allocation problem, so this rule avoids that false positive
    """

    name = "ResourceClaimPending"
    category = "Scheduling"
    priority = 88
    deterministic = False
    phases = ["Pending", "Unknown"]
    blocks = [
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
        "optional_objects": ["resourceclaim", "resourceclaimtemplate", "resourceslice"],
    }

    CACHE_KEY = "_resource_claim_pending_candidate"
    WINDOW_MINUTES = 60

    RESOURCE_CLAIM_MARKERS = (
        "resourceclaim",
        "resource claim",
        "resource.k8s.io",
    )
    PENDING_MARKERS = (
        "not allocated",
        "not yet allocated",
        "not reserved",
        "not reserved for",
        "waiting for resourceclaim",
        "waiting for resource claim",
        "waiting for allocation",
        "pending allocation",
        "allocation pending",
        "claim pending",
        "resource claim pending",
        "resourceclaim pending",
        "does not have an allocation",
        "no allocation",
        "not available yet",
    )
    NOT_FOUND_MARKERS = (
        "not found",
        "does not exist",
        "could not find",
        "no resourceclaim",
        "no resource claim",
    )

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

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
            direct_name = entry.get("resourceClaimName")
            template_name = entry.get("resourceClaimTemplateName")

            if not isinstance(logical_name, str) or not logical_name.strip():
                continue

            generated_name = claim_statuses.get(logical_name)

            refs.append(
                {
                    "logical_name": logical_name.strip(),
                    "claim_name": (
                        direct_name.strip()
                        if isinstance(direct_name, str) and direct_name.strip()
                        else generated_name
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

    def _resourceclaims(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        raw = objects.get("resourceclaim") or objects.get("resourceclaims") or {}

        if isinstance(raw, dict):
            return [obj for obj in raw.values() if isinstance(obj, dict)]

        if isinstance(raw, list):
            return [obj for obj in raw if isinstance(obj, dict)]

        return []

    def _resourceclaim_graph_present(self, context: dict[str, Any]) -> bool:
        objects = context.get("objects", {}) or {}
        return "resourceclaim" in objects or "resourceclaims" in objects

    def _find_claim(
        self,
        context: dict[str, Any],
        *,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        for claim in self._resourceclaims(context):
            metadata = claim.get("metadata", {}) or {}
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", namespace) != namespace:
                continue
            return claim
        return None

    def _claim_allocated(self, claim: dict[str, Any]) -> bool:
        allocation = claim.get("status", {}).get("allocation")
        return isinstance(allocation, dict) and bool(allocation)

    def _reserved_for_pod(
        self,
        claim: dict[str, Any],
        *,
        pod_name: str,
        pod_uid: str | None,
    ) -> bool:
        reservations = claim.get("status", {}).get("reservedFor", []) or []
        for reservation in reservations:
            if not isinstance(reservation, dict):
                continue
            resource = self._message(reservation.get("resource")).lower()
            if resource not in ("", "pods", "pod"):
                continue
            reservation_name = self._message(reservation.get("name"))
            reservation_uid = self._message(reservation.get("uid"))
            if pod_uid and reservation_uid == pod_uid:
                return True
            if reservation_name == pod_name and not pod_uid:
                return True
        return False

    def _pending_conditions(self, claim: dict[str, Any]) -> list[str]:
        messages = []
        for condition in claim.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue
            status = self._message(condition.get("status")).lower()
            if status not in ("false", "unknown"):
                continue
            cond_type = self._message(condition.get("type"))
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            combined = f"{cond_type} {reason} {message}".lower()
            if any(marker in combined for marker in self.PENDING_MARKERS):
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

    def _event_namespace_matches(
        self,
        event: dict[str, Any],
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}
        if not isinstance(involved, dict):
            return True
        event_namespace = involved.get("namespace")
        return event_namespace in (None, "", pod_namespace)

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

    def _event_mentions_claim(
        self,
        message: str,
        claim_names: set[str],
        logical_names: set[str],
    ) -> bool:
        lowered = message.lower()
        if not claim_names and not logical_names:
            return True
        for name in claim_names | logical_names:
            if name and name.lower() in lowered:
                return True
        return False

    def _looks_resourceclaim_pending_event(
        self,
        event: dict[str, Any],
        *,
        claim_names: set[str],
        logical_names: set[str],
    ) -> bool:
        message = self._message(event.get("message"))
        combined = f"{event.get('reason') or ''} {message}".lower()

        if not any(marker in combined for marker in self.RESOURCE_CLAIM_MARKERS):
            return False

        if any(marker in combined for marker in self.NOT_FOUND_MARKERS):
            return False

        if not any(marker in combined for marker in self.PENDING_MARKERS):
            return False

        return self._event_mentions_claim(message, claim_names, logical_names)

    def _matching_events(
        self,
        pod: dict[str, Any],
        refs: list[dict[str, str | None]],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        pod_namespace = self._namespace(pod)
        claim_names = {
            str(ref["claim_name"])
            for ref in refs
            if isinstance(ref.get("claim_name"), str)
        }
        logical_names = {
            str(ref["logical_name"])
            for ref in refs
            if isinstance(ref.get("logical_name"), str)
        }

        results = []
        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue
            if not self._event_namespace_matches(event, pod_namespace):
                continue
            if not self._looks_resourceclaim_pending_event(
                event,
                claim_names=claim_names,
                logical_names=logical_names,
            ):
                continue
            if not self._event_mentions_pod(
                event,
                pod_name=pod_name,
                pod_namespace=pod_namespace,
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            results.append(event)
        return results

    def _claim_pending_record(
        self,
        *,
        ref: dict[str, str | None],
        claim: dict[str, Any],
        pod: dict[str, Any],
    ) -> dict[str, Any] | None:
        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        pod_uid = self._message(pod.get("metadata", {}).get("uid")) or None
        claim_name = claim.get("metadata", {}).get("name") or ref.get("claim_name")
        allocated = self._claim_allocated(claim)
        condition_messages = self._pending_conditions(claim)

        if not allocated:
            return {
                "ref": ref,
                "claim": claim,
                "claim_name": claim_name,
                "reason": "allocation_pending",
                "condition_messages": condition_messages,
            }

        reserved_for = claim.get("status", {}).get("reservedFor", [])
        if pod_uid and not self._reserved_for_pod(
            claim,
            pod_name=pod_name,
            pod_uid=pod_uid,
        ):
            return {
                "ref": ref,
                "claim": claim,
                "claim_name": claim_name,
                "reason": "reservation_pending",
                "condition_messages": condition_messages,
                "reserved_for_count": len(reserved_for or []),
            }

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if pod.get("spec", {}).get("schedulingGates"):
            return None

        phase = get_pod_phase(pod)
        if phase not in {"Pending", "Unknown"}:
            return None

        refs = self._pod_claim_refs(pod)
        matching_events = self._matching_events(pod, refs, events, context)

        pod_namespace = self._namespace(pod)
        graph_present = self._resourceclaim_graph_present(context)
        pending_records = []
        missing_direct_refs = []
        waiting_generated_refs = []

        for ref in refs:
            claim_name = ref.get("claim_name")
            if isinstance(claim_name, str) and claim_name:
                claim = self._find_claim(
                    context, name=claim_name, namespace=pod_namespace
                )
                if claim is None:
                    if ref.get("source") == "direct":
                        missing_direct_refs.append(ref)
                    elif graph_present:
                        waiting_generated_refs.append(ref)
                    continue

                record = self._claim_pending_record(ref=ref, claim=claim, pod=pod)
                if record is not None:
                    pending_records.append(record)
                continue

            if ref.get("template_name") and graph_present:
                waiting_generated_refs.append(ref)

        if pending_records:
            return {
                "refs": refs,
                "pending_records": pending_records,
                "waiting_generated_refs": waiting_generated_refs,
                "missing_direct_refs": missing_direct_refs,
                "events": matching_events,
                "graph_present": graph_present,
            }

        if matching_events and refs:
            return {
                "refs": refs,
                "pending_records": [],
                "waiting_generated_refs": waiting_generated_refs,
                "missing_direct_refs": missing_direct_refs,
                "events": matching_events,
                "graph_present": graph_present,
            }

        if waiting_generated_refs and not missing_direct_refs:
            return {
                "refs": refs,
                "pending_records": [],
                "waiting_generated_refs": waiting_generated_refs,
                "missing_direct_refs": missing_direct_refs,
                "events": matching_events,
                "graph_present": graph_present,
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
            raise ValueError("ResourceClaimPending explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = self._namespace(pod)
        pending_records = candidate.get("pending_records", [])
        waiting_generated_refs = candidate.get("waiting_generated_refs", [])
        matching_events = candidate.get("events", [])

        claim_names = [
            str(record.get("claim_name"))
            for record in pending_records
            if record.get("claim_name")
        ]
        waiting_templates = [
            str(ref.get("template_name"))
            for ref in waiting_generated_refs
            if ref.get("template_name")
        ]
        ref_names = [
            str(ref.get("logical_name"))
            for ref in candidate.get("refs", [])
            if ref.get("logical_name")
        ]

        claim_display = ", ".join(claim_names or waiting_templates or ref_names)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REFERENCES_RESOURCECLAIM",
                    message=f"Pod references dynamic resource claim(s): {claim_display}",
                    role="workload_context",
                ),
                Cause(
                    code="RESOURCECLAIM_PENDING",
                    message="Required ResourceClaim allocation or reservation has not completed",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_WAITING_FOR_DYNAMIC_RESOURCE",
                    message="Pod cannot be scheduled or started until the DRA claim is allocated and reserved",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
            f"Pod.spec.resourceClaims={', '.join(ref_names)}",
        ]
        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                f"References ResourceClaim entry/entries: {', '.join(ref_names)}",
            ]
        }

        for record in pending_records:
            claim_name = str(record.get("claim_name") or "<unknown>")
            reason = record.get("reason")
            claim_key = f"resourceclaim:{namespace}/{claim_name}"
            object_evidence.setdefault(claim_key, [])

            if reason == "allocation_pending":
                evidence.append(f"ResourceClaim {claim_name} has no status.allocation")
                object_evidence[claim_key].append("status.allocation is not set")
            elif reason == "reservation_pending":
                evidence.append(
                    f"ResourceClaim {claim_name} is allocated but not reserved for this Pod"
                )
                object_evidence[claim_key].append(
                    "status.reservedFor does not include this Pod"
                )

            for condition_message in record.get("condition_messages", []):
                evidence.append(condition_message)
                object_evidence[claim_key].append(condition_message)

        for ref in waiting_generated_refs:
            logical_name = ref.get("logical_name")
            template_name = ref.get("template_name")
            evidence.append(
                f"Generated ResourceClaim for Pod claim '{logical_name}' from template '{template_name}' is not visible yet"
            )
            object_evidence[f"pod:{namespace}/{pod_name}"].append(
                f"Waiting for generated ResourceClaim from template {template_name}"
            )

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]
        if event_messages:
            evidence.append(
                f"ResourceClaim pending event observed {len(event_messages)} time(s)"
            )
            evidence.extend(event_messages[:2])
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(event_messages[:3])

        confidence = 0.9
        if pending_records and event_messages:
            confidence = 0.96
        elif pending_records:
            confidence = 0.94
        elif waiting_generated_refs:
            confidence = 0.88

        return {
            "rule": self.name,
            "root_cause": "Pod is waiting for a Dynamic Resource Allocation ResourceClaim",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "The DRA scheduler has not found a ResourceSlice/device satisfying the claim",
                "The dynamic resource driver is delayed, unhealthy, or unable to allocate the requested device",
                "The ResourceClaimTemplate-generated ResourceClaim has not been created yet",
                "The claim is allocated but not reserved for this Pod because another consumer holds it or scheduler reservation failed",
                "DRA feature gates, scheduler configuration, or resource.k8s.io driver RBAC are misconfigured",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl get resourceclaim -n {namespace}",
                f"kubectl describe resourceclaim <claim-name> -n {namespace}",
                "kubectl get resourceslice -A",
                "Check the DRA driver/controller logs and resource.k8s.io RBAC permissions",
                "Verify ResourceClaim.status.allocation and status.reservedFor include the affected Pod",
            ],
        }
