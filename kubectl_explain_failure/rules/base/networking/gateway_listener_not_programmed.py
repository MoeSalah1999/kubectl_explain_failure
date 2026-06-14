from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class GatewayListenerNotProgrammedRule(FailureRule):
    """
    Detects Gateway API failures where one or more Gateway listeners are
    not successfully programmed by the Gateway controller.

    Real-world behavior:
    - Listener Accepted=False
    - Listener Programmed=False
    - Listener ResolvedRefs=False
    - Listener Conflicted=True
    - Listener Invalid / PortUnavailable / UnsupportedProtocol
    - Listener rejected due to hostname, port, protocol or TLS config
    - Gateway controller emits reconciliation failures

    Exclusions:
    - Missing GatewayClass (GatewayClassUnavailable)
    - Missing TLS Secret (IngressTLSSecretMissing)
    - Invalid backend Service (IngressBackendServiceInvalid)
    - Route attachment failures handled by dedicated rules.
    """

    name = "GatewayListenerNotProgrammed"
    category = "Networking"
    severity = "High"
    priority = 85
    deterministic = True

    phases = ["Pending", "Running", "Succeeded", "Failed"]

    requires = {
        "pod": False,
        "context": ["timeline"],
        "optional_objects": [
            "gateway",
        ],
    }

    blocks = []

    WINDOW_MINUTES = 30

    FAILURE_REASONS = {
        "invalid",
        "invalidroutekinds",
        "invalidcertificate",
        "invalidtls",
        "portunavailable",
        "unsupportedprotocol",
        "conflicted",
        "listenerconflicted",
        "hostnameconflict",
        "resolvedrefsfalse",
        "pending",
    }

    EVENT_MARKERS = (
        "listener",
        "programmed",
        "accepted",
        "resolvedrefs",
        "gateway",
        "port unavailable",
        "unsupported protocol",
        "listener rejected",
        "listener conflict",
        "hostname conflict",
        "failed to program listener",
        "failed to reconcile listener",
        "invalid listener",
        "listener not programmed",
    )

    CONTROLLER_HINTS = (
        "gateway",
        "gateway-api",
        "envoy",
        "istio",
        "contour",
        "kong",
        "traefik",
        "haproxy",
    )

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _event_text(self, event: dict[str, Any]) -> str:
        return (
            f"{event.get('type','')} "
            f"{self._reason(event)} "
            f"{self._message(event)}"
        ).lower()

    def _event_matches(self, event: dict[str, Any]) -> bool:
        text = self._event_text(event)

        if not any(h in text for h in self.CONTROLLER_HINTS):
            return False

        return any(marker in text for marker in self.EVENT_MARKERS)

    def _listener_name(self, listener_status: dict[str, Any]) -> str:
        return str(listener_status.get("name") or "<unknown>")

    def _condition_failure(
        self,
        cond: dict[str, Any],
    ) -> tuple[bool, str]:
        cond_type = str(cond.get("type") or "")
        status = str(cond.get("status") or "")
        reason = str(cond.get("reason") or "")
        message = str(cond.get("message") or "")

        reason_lower = reason.lower()

        #
        # Accepted=False
        #
        if cond_type == "Accepted" and status == "False":
            return True, reason or message

        #
        # Programmed=False
        #
        if cond_type == "Programmed" and status == "False":
            return True, reason or message

        #
        # ResolvedRefs=False
        #
        if cond_type == "ResolvedRefs" and status == "False":
            return True, reason or message

        #
        # Conflicted=True
        #
        if cond_type == "Conflicted" and status == "True":
            return True, reason or message

        #
        # Known failure reasons
        #
        if reason_lower in self.FAILURE_REASONS:
            return True, reason or message

        return False, ""

    def _candidate(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        gateways = context.get("objects", {}).get("gateway", {})

        failures: list[dict[str, Any]] = []
        object_evidence: dict[str, list[str]] = {}

        for gateway in gateways.values():
            if not isinstance(gateway, dict):
                continue

            md = gateway.get("metadata", {})
            gw_name = md.get("name", "<unknown>")
            namespace = md.get("namespace", "default")

            listener_statuses = gateway.get("status", {}).get("listeners", []) or []

            for listener in listener_statuses:
                listener_name = self._listener_name(listener)

                for cond in listener.get("conditions", []) or []:
                    failed, detail = self._condition_failure(cond)

                    if not failed:
                        continue

                    cond_type = str(cond.get("type") or "")

                    failures.append(
                        {
                            "gateway": gw_name,
                            "namespace": namespace,
                            "listener": listener_name,
                            "condition": cond_type,
                            "detail": detail,
                        }
                    )

                    object_evidence.setdefault(
                        f"gateway:{namespace}/{gw_name}",
                        [],
                    ).append(
                        f"Listener '{listener_name}' " f"{cond_type}=False"
                        if cond_type != "Conflicted"
                        else f"Listener '{listener_name}' Conflicted=True"
                    )

                    if detail:
                        object_evidence[f"gateway:{namespace}/{gw_name}"].append(detail)

        matching_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._event_matches(e)
        ]

        if not failures and not matching_events:
            return None

        return {
            "failures": failures,
            "events": matching_events,
            "object_evidence": object_evidence,
        }

    # ------------------------------------------------------------------ #
    # Rule API
    # ------------------------------------------------------------------ #

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        return self._candidate(context) is not None

    def explain(
        self,
        pod,
        events,
        context,
    ):
        candidate = self._candidate(context)

        if candidate is None:
            raise ValueError(
                "GatewayListenerNotProgrammed explain() called without match"
            )

        evidence: list[str] = []

        for failure in candidate["failures"]:
            msg = (
                f"Gateway {failure['namespace']}/"
                f"{failure['gateway']} "
                f"listener '{failure['listener']}' "
                f"failed {failure['condition']}"
            )

            if failure["detail"]:
                msg += f": {failure['detail']}"

            evidence.append(msg)

        for event in candidate["events"][:3]:
            text = self._message(event)
            if text:
                evidence.append(text)

        chain = CausalChain(
            causes=[
                Cause(
                    code="GATEWAY_LISTENER_DEFINED",
                    message="Gateway listener is configured",
                    role="runtime_context",
                ),
                Cause(
                    code="GATEWAY_LISTENER_NOT_PROGRAMMED",
                    message="Gateway controller cannot successfully program the listener",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="LISTENER_CANNOT_ACCEPT_TRAFFIC",
                    message="Gateway listener is unavailable for traffic",
                    role="workload_symptom",
                ),
            ]
        )

        confidence = 0.90

        if candidate["failures"]:
            confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": (
                "Gateway listener could not be programmed by the Gateway controller"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v))
                for k, v in candidate["object_evidence"].items()
            },
            "likely_causes": [
                "Listener configuration is invalid",
                "Listener has unresolved references",
                "Listener port conflicts with another listener",
                "Hostname conflict exists",
                "Unsupported protocol was configured",
                "TLS configuration prevents listener programming",
                "Gateway controller rejected the listener configuration",
            ],
            "suggested_checks": [
                "kubectl get gateway -A -o yaml",
                "kubectl describe gateway <gateway-name>",
                "Inspect status.listeners.conditions on the Gateway",
                "Verify Programmed, Accepted and ResolvedRefs conditions",
                "Check Gateway controller logs",
                "Verify listener ports, hostnames and protocols",
                "Verify listener TLS configuration and referenced objects",
            ],
        }
