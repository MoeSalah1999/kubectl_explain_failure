from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class HTTPRouteNotAcceptedRule(FailureRule):
    """
    Detects Gateway API HTTPRoute resources that are not Accepted by
    their parent Gateway.

    Real-world behavior:
    - Gateway controller sets status.parents[].conditions[type=Accepted]
      on HTTPRoute resources.
    - Accepted=False prevents route programming and traffic forwarding.
    - Common causes:
        * hostname mismatch
        * parentRef points to non-existent Gateway
        * cross-namespace attachment denied
        * listener protocol mismatch
        * listener hostname restrictions
        * Route kind not allowed by listener
        * controller validation rejection
    - Route may exist and be syntactically valid while still never
      becoming active due to Accepted=False.

    Exclusions:
    - Gateway itself not programmed (GatewayNotProgrammed should own)
    - BackendRef failures (BackendNotFound, ServiceMissing, etc.)
    - DNS / LoadBalancer reachability issues after successful attachment
    """

    name = "HTTPRouteNotAccepted"
    category = "Networking"
    severity = "High"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "httproute",
            "gateway",
            "referencegrant",
        ],
    }

    WINDOW_MINUTES = 30

    ACCEPTED_FALSE_REASONS = {
        "notallowedbylisteners",
        "unsupportedvalue",
        "invalidkind",
        "invalidroutekinds",
        "nomatchinglistenerhostname",
        "hostnamemismatch",
        "parentrefnotpermitted",
        "refnotpermitted",
        "backendnotpermitted",
        "routeconflict",
        "invalid",
        "detached",
        "targetnotfound",
    }

    ROUTE_EVENT_MARKERS = (
        "httproute",
        "gateway.networking.k8s.io",
        "parentref",
        "accepted",
        "listener",
        "hostname",
        "route attachment",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _find_candidate_routes(
        self,
        context: dict[str, Any],
        pod: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Try to locate HTTPRoutes relevant to the workload namespace.

        We intentionally avoid strict ownership assumptions because
        many environments do not populate relations yet.
        """
        namespace = pod.get("metadata", {}).get("namespace")

        routes = []

        for route in context.get("objects", {}).get("httproute", {}).values():
            if not isinstance(route, dict):
                continue

            route_ns = route.get("metadata", {}).get("namespace")

            if namespace and route_ns == namespace:
                routes.append(route)

        return routes

    def _accepted_condition(
        self,
        route: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Search all parent statuses for Accepted=False.
        """
        status = route.get("status", {}) or {}

        for parent in status.get("parents", []) or []:
            for condition in parent.get("conditions", []) or []:
                if condition.get("type") != "Accepted":
                    continue

                accepted = str(condition.get("status", "")).lower()

                if accepted == "false":
                    return condition, (parent.get("parentRef", {}) or {}).get("name")

        return None, None

    def _route_rejection_reason(
        self,
        condition: dict[str, Any],
    ) -> str:
        reason = str(condition.get("reason") or "")
        message = str(condition.get("message") or "")

        if reason:
            return f"{reason}: {message}".strip(": ")

        return message or "Gateway controller rejected route attachment"

    def _rejection_event(
        self,
        timeline: Timeline,
        route_name: str,
    ) -> dict[str, Any] | None:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        for event in reversed(recent):
            msg = self._message(event).lower()

            if route_name.lower() not in msg:
                continue

            if any(marker in msg for marker in self.ROUTE_EVENT_MARKERS):
                return event

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        routes = self._find_candidate_routes(context, pod)

        for route in routes:
            condition, gateway_name = self._accepted_condition(route)

            if not condition:
                continue

            route_name = self._object_name(route)
            namespace = self._object_namespace(route)

            reason_text = self._route_rejection_reason(condition)

            event = self._rejection_event(
                timeline,
                route_name,
            )

            object_evidence = {
                f"httproute:{route_name}": [f"Accepted=False ({reason_text})"]
            }

            if gateway_name:
                object_evidence[f"gateway:{gateway_name}"] = [
                    "Gateway rejected HTTPRoute attachment"
                ]

            return {
                "route_name": route_name,
                "namespace": namespace,
                "gateway_name": gateway_name,
                "reason": reason_text,
                "condition": condition,
                "event": event,
                "object_evidence": object_evidence,
            }

        return None

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("HTTPRouteNotAccepted requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("HTTPRouteNotAccepted explain() called without match")

        route_name = candidate["route_name"]
        namespace = candidate["namespace"]
        gateway_name = candidate["gateway_name"]
        rejection_reason = candidate["reason"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="HTTPROUTE_REFERENCES_GATEWAY",
                    message="HTTPRoute depends on successful attachment to a Gateway listener",
                    role="runtime_context",
                ),
                Cause(
                    code="HTTPROUTE_NOT_ACCEPTED",
                    message="Gateway controller rejected or refused HTTPRoute attachment",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="ROUTE_NOT_PROGRAMMED",
                    message="Traffic cannot be routed because the HTTPRoute was never accepted",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"HTTPRoute {namespace}/{route_name} reports Accepted=False",
            f"Gateway controller rejection reason: {rejection_reason}",
        ]

        if gateway_name:
            evidence.append(f"Rejected by Gateway {gateway_name}")

        if candidate["event"]:
            evidence.append(
                f"Recent route-related event: {self._message(candidate['event'])}"
            )

        confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": "HTTPRoute was rejected by its parent Gateway",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "HTTPRoute hostname does not match any Gateway listener hostname",
                "ParentRef references a Gateway that does not exist",
                "Cross-namespace route attachment is not permitted",
                "Gateway listener does not allow HTTPRoute attachments",
                "Listener protocol or route kind is incompatible",
                "Gateway controller validation rejected the route configuration",
                "Route conflicts with another attached route",
            ],
            "suggested_checks": [
                f"kubectl describe httproute {route_name} -n {namespace}",
                f"kubectl get httproute {route_name} -n {namespace} -o yaml",
                "Inspect status.parents[].conditions for Accepted=False",
                "Verify parentRefs point to the intended Gateway",
                "Check Gateway listener hostname and allowedRoutes configuration",
                "Verify ReferenceGrant resources for cross-namespace attachments",
                (
                    f"kubectl describe gateway {gateway_name}"
                    if gateway_name
                    else "kubectl get gateways -A"
                ),
            ],
        }
