from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class CapacityReservationMismatchRule(FailureRule):
    """
    Detect Pods that explicitly target a Capacity Reservation but cannot
    consume it because the reservation is incompatible, exhausted, or
    otherwise unavailable.

    Real-world behavior:
    - Reservation-aware schedulers (Koordinator, OpenKruise, cloud-provider
      reservation implementations, etc.) emit FailedScheduling events when a
      reservation cannot satisfy a Pod.
    - Reservation objects often expose availability, allocatable capacity,
      owners/selectors, node constraints, and status conditions.
    - A reservation existing is not sufficient; the Pod must be eligible
      to consume it.
    """

    name = "CapacityReservationMismatch"
    category = "Scheduling"
    priority = 92
    deterministic = False

    phases = ["Pending", "Unknown"]

    blocks = [
        "FailedScheduling",
        "PendingUnschedulable",
        "InsufficientResources",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "UnschedulableTaint",
    ]

    requires = {
        "pod": True,
        "optional_objects": [
            "reservation",
            "reservations",
            "capacityreservation",
            "capacityreservations",
        ],
    }

    CACHE_KEY = "_capacity_reservation_mismatch_candidate"
    WINDOW_MINUTES = 60

    RESERVATION_MARKERS = (
        "reservation",
        "capacity reservation",
        "capacityreservation",
        "reserved capacity",
        "reservation affinity",
        "reservation selector",
        "reservation owner",
        "reservation mismatch",
    )

    MISMATCH_MARKERS = (
        "not match",
        "does not match",
        "mismatch",
        "not eligible",
        "reservation not available",
        "reservation unavailable",
        "cannot allocate from reservation",
        "reservation exhausted",
        "insufficient reserved resources",
        "reservation selector mismatch",
        "reservation affinity mismatch",
        "reservation owner mismatch",
        "reservation taint",
        "reservation filtered",
        "reservation rejected",
        "reservation not schedulable",
        "no matching reservation",
        "no available reservation",
    )

    def _msg(self, value: Any) -> str:
        return str(value or "").strip()

    def _namespace(self, obj: dict[str, Any]) -> str:
        return self._msg(obj.get("metadata", {}).get("namespace")) or "default"

    def _object_list(
        self,
        context: dict[str, Any],
        *names: str,
    ) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        results: list[dict[str, Any]] = []

        for name in names:
            raw = objects.get(name)

            if isinstance(raw, list):
                results.extend(x for x in raw if isinstance(x, dict))

            elif isinstance(raw, dict):
                if "metadata" in raw:
                    results.append(raw)
                else:
                    results.extend(x for x in raw.values() if isinstance(x, dict))

        return results

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

    def _reservation_objects(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return self._object_list(
            context,
            "reservation",
            "reservations",
            "capacityreservation",
            "capacityreservations",
        )

    def _pod_references_reservation(
        self,
        pod: dict[str, Any],
    ) -> bool:
        spec = pod.get("spec", {}) or {}
        annotations = pod.get("metadata", {}).get("annotations", {}) or {}

        text = " ".join(
            [
                str(spec),
                " ".join(f"{k}={v}" for k, v in annotations.items()),
            ]
        ).lower()

        return any(marker in text for marker in self.RESERVATION_MARKERS)

    def _reservation_conditions(
        self,
        reservation: dict[str, Any],
    ) -> list[str]:
        findings = []

        for condition in reservation.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue

            cond_type = self._msg(condition.get("type"))
            reason = self._msg(condition.get("reason"))
            message = self._msg(condition.get("message"))
            status = self._msg(condition.get("status"))

            combined = f"{cond_type} {reason} {message}".lower()

            if any(x in combined for x in self.MISMATCH_MARKERS):
                findings.append(
                    f"Reservation condition {cond_type}={status} reason={reason}"
                )

            if cond_type.lower() in ("available", "ready") and status.lower() in (
                "false",
                "unknown",
            ):
                findings.append(f"Reservation reports {cond_type}={status}")

        return findings

    def _reservation_capacity_signals(
        self,
        reservation: dict[str, Any],
    ) -> list[str]:
        findings = []

        status = reservation.get("status", {}) or {}

        allocatable = status.get("allocatable")
        allocated = status.get("allocated")

        if isinstance(allocatable, dict) and isinstance(allocated, dict):
            cpu_total = allocatable.get("cpu")
            cpu_used = allocated.get("cpu")

            if cpu_total is not None and cpu_used == cpu_total:
                findings.append("Reservation CPU capacity is fully allocated")

        unavailable = status.get("unavailable")

        if unavailable is True:
            findings.append("Reservation is marked unavailable")

        return findings

    def _reservation_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pod_name = self._msg(pod.get("metadata", {}).get("name"))

        matches = []

        for event in self._candidate_events(events, context):
            message = self._msg(event.get("message"))
            reason = self._msg(event.get("reason"))

            combined = f"{reason} {message}".lower()

            if not any(marker in combined for marker in self.RESERVATION_MARKERS):
                continue

            if not any(marker in combined for marker in self.MISMATCH_MARKERS):
                continue

            if pod_name and pod_name.lower() not in combined:
                involved = event.get("involvedObject") or {}
                if involved.get("kind") == "Pod":
                    if involved.get("name") != pod_name:
                        continue

            matches.append(event)

        return matches

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if get_pod_phase(pod) not in {"Pending", "Unknown"}:
            return None

        reservations = self._reservation_objects(context)

        pod_refs_reservation = self._pod_references_reservation(pod)

        reservation_signals: list[str] = []

        for reservation in reservations:
            reservation_signals.extend(self._reservation_conditions(reservation))
            reservation_signals.extend(self._reservation_capacity_signals(reservation))

        matching_events = self._reservation_events(
            pod,
            events,
            context,
        )

        if not (pod_refs_reservation or reservation_signals or matching_events):
            return None

        if not reservation_signals and not matching_events:
            return None

        return {
            "reservations": reservations,
            "signals": list(dict.fromkeys(reservation_signals)),
            "events": matching_events,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(
            pod,
            events,
            context,
        )

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, events, context)

        if candidate is None:
            raise ValueError(
                "CapacityReservationMismatch explain() called without match"
            )

        pod_name = self._msg(pod.get("metadata", {}).get("name")) or "<unknown>"

        namespace = self._namespace(pod)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_TARGETS_RESERVATION",
                    message="Pod is attempting to consume reserved capacity",
                    role="workload_context",
                ),
                Cause(
                    code="CAPACITY_RESERVATION_MISMATCH",
                    message="Target reservation is incompatible, unavailable, or exhausted",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE",
                    message="Pod cannot be scheduled using the requested reservation",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
        ]

        evidence.extend(candidate["signals"])

        event_messages = [
            self._msg(e.get("message"))
            for e in candidate["events"]
            if self._msg(e.get("message"))
        ]

        evidence.extend(event_messages[:3])

        object_evidence = {
            f"pod:{namespace}/{pod_name}": event_messages[:3],
        }

        for reservation in candidate["reservations"]:
            name = self._msg(reservation.get("metadata", {}).get("name"))

            if not name:
                continue

            object_evidence[f"reservation:{name}"] = self._reservation_conditions(
                reservation
            ) + self._reservation_capacity_signals(reservation)

        confidence = 0.90

        if candidate["signals"] and event_messages:
            confidence = 0.97

        return {
            "rule": self.name,
            "root_cause": ("Pod cannot consume the requested Capacity Reservation"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": object_evidence,
            "likely_causes": [
                "Reservation selector or owner rules do not match the Pod",
                "Reservation capacity has already been consumed",
                "Reservation node constraints conflict with Pod scheduling constraints",
                "Reservation is marked unavailable or not ready",
                "Reservation-specific scheduler plugin rejected the Pod",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get reservations -A",
                "kubectl describe reservation <reservation-name>",
                "Check reservation owner/selector rules",
                "Check allocatable versus allocated reservation capacity",
                "Review scheduler FailedScheduling events",
            ],
        }
