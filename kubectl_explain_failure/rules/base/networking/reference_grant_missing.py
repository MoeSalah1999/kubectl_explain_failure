from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ReferenceGrantMissingRule(FailureRule):
    """
    Detects Gateway API cross-namespace references that require a
    ReferenceGrant but none exists.

    Real-world behavior:
    - Gateway API forbids cross-namespace object references unless
      explicitly authorized by a ReferenceGrant.
    - Common examples:
        * HTTPRoute backendRef -> Service in another namespace
        * HTTPRoute backendRef -> ServiceImport in another namespace
        * Gateway listener certificateRef -> Secret in another namespace
        * Route parentRef -> Gateway in another namespace (implementation-specific)
    - Gateway controllers surface Accepted=False, ResolvedRefs=False,
      RefNotPermitted, ReferenceNotPermitted, BackendNotFound,
      InvalidRouteKinds, or similar conditions.
    - The route may exist and be otherwise valid, but traffic is blocked
      because the controller refuses to resolve the cross-namespace reference.

    Exclusions:
    - Missing backend object itself (ServiceMissing should own).
    - Invalid ReferenceGrant contents when a grant actually exists.
    - Route hostname, listener, or attachment failures unrelated to
      cross-namespace authorization.
    """

    name = "ReferenceGrantMissing"
    category = "Networking"
    severity = "High"
    priority = 81
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "httproute",
            "gateway",
            "referencegrant",
            "service",
            "secret",
        ],
    }

    WINDOW_MINUTES = 30

    REF_NOT_PERMITTED_REASONS = {
        "refnotpermitted",
        "referencenotpermitted",
        "backendnotpermitted",
        "targetnotpermitted",
    }

    RESOLVED_REFS_FAILURE_REASONS = {
        "refnotpermitted",
        "referencenotpermitted",
        "backendnotfound",
        "invalidreference",
    }

    EVENT_MARKERS = (
        "referencegrant",
        "refnotpermitted",
        "referencenotpermitted",
        "cross-namespace",
        "not permitted",
        "resolvedrefs",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _find_routes(
        self,
        context: dict[str, Any],
        pod: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pod_ns = pod.get("metadata", {}).get("namespace")

        routes = []

        for route in context.get("objects", {}).get("httproute", {}).values():
            if not isinstance(route, dict):
                continue

            if route.get("metadata", {}).get("namespace") == pod_ns:
                routes.append(route)

        return routes

    def _grant_matches(
        self,
        grant: dict[str, Any],
        route_namespace: str,
        target_namespace: str,
    ) -> bool:
        """
        Conservative ReferenceGrant validation.

        We intentionally validate only the parts necessary
        to establish that authorization exists.
        """

        metadata_ns = grant.get("metadata", {}).get("namespace")

        if metadata_ns != target_namespace:
            return False

        spec = grant.get("spec", {}) or {}

        from_entries = spec.get("from", []) or []

        for entry in from_entries:
            if not isinstance(entry, dict):
                continue

            if entry.get("namespace") != route_namespace:
                continue

            group = str(entry.get("group") or "")

            if group in (
                "",
                "gateway.networking.k8s.io",
            ):
                return True

        return False

    def _has_reference_grant(
        self,
        context: dict[str, Any],
        route_namespace: str,
        target_namespace: str,
    ) -> bool:
        grants = context.get("objects", {}).get("referencegrant", {})

        for grant in grants.values():
            if isinstance(grant, dict) and self._grant_matches(
                grant,
                route_namespace,
                target_namespace,
            ):
                return True

        return False

    def _cross_namespace_backend_refs(
        self,
        route: dict[str, Any],
    ) -> list[dict[str, str]]:
        route_ns = self._object_namespace(route)

        refs: list[dict[str, str]] = []

        for rule in route.get("spec", {}).get("rules", []) or []:
            for backend in rule.get("backendRefs", []) or []:
                if not isinstance(backend, dict):
                    continue

                target_ns = backend.get("namespace")

                if not target_ns or target_ns == route_ns:
                    continue

                refs.append(
                    {
                        "namespace": str(target_ns),
                        "name": str(backend.get("name") or ""),
                        "kind": str(backend.get("kind") or "Service"),
                    }
                )

        return refs

    def _route_condition_failure(
        self,
        route: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        status = route.get("status", {}) or {}

        for parent in status.get("parents", []) or []:
            for condition in parent.get("conditions", []) or []:

                cond_type = str(condition.get("type") or "")
                cond_status = str(condition.get("status") or "").lower()
                cond_reason = str(condition.get("reason") or "")

                if cond_status != "false":
                    continue

                reason_key = cond_reason.lower()

                if (
                    cond_type == "ResolvedRefs"
                    and reason_key in self.RESOLVED_REFS_FAILURE_REASONS
                ):
                    return cond_reason, str(condition.get("message") or "")

                if (
                    cond_type == "Accepted"
                    and reason_key in self.REF_NOT_PERMITTED_REASONS
                ):
                    return cond_reason, str(condition.get("message") or "")

        return None, None

    def _matching_event(
        self,
        timeline: Timeline,
        route_name: str,
    ) -> dict[str, Any] | None:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        for event in reversed(recent):
            msg = self._message(event).lower()

            if route_name.lower() not in msg:
                continue

            if any(marker in msg for marker in self.EVENT_MARKERS):
                return event

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        routes = self._find_routes(context, pod)

        for route in routes:

            route_name = self._object_name(route)
            route_ns = self._object_namespace(route)

            reason, message = self._route_condition_failure(route)

            refs = self._cross_namespace_backend_refs(route)

            if not refs:
                continue

            for ref in refs:

                target_ns = ref["namespace"]

                if self._has_reference_grant(
                    context,
                    route_ns,
                    target_ns,
                ):
                    continue

                event = self._matching_event(
                    timeline,
                    route_name,
                )

                object_evidence = {
                    f"httproute:{route_name}": [
                        (reason and f"{reason}: {message}")
                        or (
                            f"Cross-namespace reference to "
                            f"{ref['kind']} {target_ns}/{ref['name']} "
                            "without ReferenceGrant"
                        )
                    ]
                }

                object_evidence[f"{ref['kind'].lower()}:{ref['name']}"] = [
                    (
                        f"Referenced from namespace {route_ns} "
                        f"but target namespace is {target_ns}"
                    )
                ]

                return {
                    "route_name": route_name,
                    "route_namespace": route_ns,
                    "target_namespace": target_ns,
                    "target_name": ref["name"],
                    "target_kind": ref["kind"],
                    "reason": reason,
                    "message": message,
                    "event": event,
                    "object_evidence": object_evidence,
                }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("ReferenceGrantMissing requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("ReferenceGrantMissing explain() called without match")

        route_name = candidate["route_name"]
        route_ns = candidate["route_namespace"]
        target_ns = candidate["target_namespace"]
        target_kind = candidate["target_kind"]
        target_name = candidate["target_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CROSS_NAMESPACE_REFERENCE",
                    message=(
                        "Gateway API object references a resource "
                        "in another namespace"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="REFERENCEGRANT_MISSING",
                    message=(
                        "No ReferenceGrant authorizes the " "cross-namespace reference"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="REFERENCE_REJECTED",
                    message=(
                        "Gateway controller refuses to resolve "
                        "the cross-namespace reference"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"HTTPRoute {route_ns}/{route_name} references "
                f"{target_kind} {target_ns}/{target_name}"
            ),
            (f"No matching ReferenceGrant exists in namespace " f"{target_ns}"),
        ]

        if candidate["reason"]:
            evidence.append(f"Controller condition reason: {candidate['reason']}")

        if candidate["message"]:
            evidence.append(f"Controller message: {candidate['message']}")

        if candidate["event"]:
            evidence.append(f"Recent event: {self._message(candidate['event'])}")

        return {
            "rule": self.name,
            "root_cause": (
                "Cross-namespace Gateway API reference is not "
                "authorized by a ReferenceGrant"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "HTTPRoute backendRef points to a Service in another namespace",
                "The destination namespace does not contain a ReferenceGrant",
                "ReferenceGrant was deleted after route creation",
                "ReferenceGrant exists but authorizes a different namespace",
                "ReferenceGrant exists but authorizes a different resource kind",
                "Gateway controller rejected the cross-namespace reference with RefNotPermitted",
            ],
            "suggested_checks": [
                f"kubectl get httproute {route_name} -n {route_ns} -o yaml",
                f"kubectl get referencegrant -n {target_ns}",
                (
                    "Inspect HTTPRoute status.parents[].conditions "
                    "for ResolvedRefs=False or RefNotPermitted"
                ),
                (
                    "Verify the ReferenceGrant exists in the target namespace "
                    f"({target_ns})"
                ),
                ("Verify ReferenceGrant.spec.from matches " f"namespace {route_ns}"),
                (
                    "Verify ReferenceGrant.spec.to allows the referenced "
                    f"{target_kind}"
                ),
            ],
        }
