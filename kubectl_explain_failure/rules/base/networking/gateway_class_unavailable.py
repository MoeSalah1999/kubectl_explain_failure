from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class GatewayClassUnavailableRule(FailureRule):
    """
    Detects Gateway API failures caused by an unavailable or invalid
    GatewayClass.

    Real-world behavior:
    - Gateway references a GatewayClass that does not exist.
    - GatewayClass exists but has not been accepted by its controller.
    - GatewayClass controller is unavailable or not installed.
    - Gateway controller reports Accepted=False / Invalid / Pending.
    - Gateway events indicate unknown GatewayClass or controller.
    - Gateway never becomes programmed because its GatewayClass
      cannot be resolved.

    Exclusions:
    - Invalid listener configuration.
    - Missing TLS Secrets.
    - Backend Service failures.
    - Route attachment failures.
    - Data-plane pod failures after successful Gateway provisioning.
    """

    name = "GatewayClassUnavailable"
    category = "Networking"
    severity = "High"
    priority = 86
    deterministic = True

    phases = ["Pending", "Running", "Succeeded", "Failed"]

    requires = {
        "pod": False,
        "context": ["timeline"],
        "optional_objects": [
            "gateway",
            "gatewayclass",
        ],
    }

    WINDOW_MINUTES = 30

    EVENT_MARKERS = (
        "gatewayclass",
        "gateway class",
        "unknown gatewayclass",
        "gatewayclass not found",
        "gateway class not found",
        "failed to get gatewayclass",
        "failed to fetch gatewayclass",
        "does not exist",
        "not found",
        "waiting for controller",
        "no controller",
        "unaccepted",
        "accepted=false",
        "invalid gatewayclass",
    )

    CONTROLLER_HINTS = (
        "gateway",
        "gateway-api",
        "envoy",
        "istio",
        "kong",
        "contour",
        "traefik",
        "haproxy",
        "gatewayclass",
    )

    NEGATIVE_ACCEPT_REASONS = {
        "invalid",
        "invalidparameters",
        "gatewayclassnotfound",
        "pending",
        "waiting",
        "unsupported",
        "unsupportedvalue",
        "nocontroller",
    }

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

    # ------------------------------------------------------------------ #
    # object helpers
    # ------------------------------------------------------------------ #

    def _gatewayclasses(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        objs = context.get("objects", {}).get("gatewayclass", {})
        return {name: obj for name, obj in objs.items() if isinstance(obj, dict)}

    def _gateways(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [
            obj
            for obj in context.get("objects", {}).get("gateway", {}).values()
            if isinstance(obj, dict)
        ]

    def _find_gatewayclass(
        self,
        context: dict[str, Any],
        name: str,
    ) -> dict[str, Any] | None:
        classes = self._gatewayclasses(context)

        if name in classes:
            return classes[name]

        for obj in classes.values():
            md = obj.get("metadata", {})
            if md.get("name") == name:
                return obj

        return None

    def _accepted_condition(
        self,
        gc: dict[str, Any],
    ) -> tuple[bool | None, str, str]:
        for cond in gc.get("status", {}).get("conditions", []) or []:
            if cond.get("type") != "Accepted":
                continue

            status = str(cond.get("status") or "")
            reason = str(cond.get("reason") or "")
            message = str(cond.get("message") or "")

            if status == "True":
                return True, reason, message

            if status == "False":
                return False, reason, message

        return None, "", ""

    # ------------------------------------------------------------------ #
    # candidate
    # ------------------------------------------------------------------ #

    def _candidate(
        self,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        gateways = self._gateways(context)

        if not gateways:
            return None

        missing: list[tuple[str, str]] = []
        unaccepted: list[tuple[str, str, str]] = []

        object_evidence: dict[str, list[str]] = {}

        for gw in gateways:
            md = gw.get("metadata", {})
            gw_name = md.get("name", "<unknown>")

            gc_name = gw.get("spec", {}).get("gatewayClassName")

            if not gc_name:
                continue

            gc = self._find_gatewayclass(
                context,
                gc_name,
            )

            if gc is None:
                missing.append(
                    (
                        gw_name,
                        gc_name,
                    )
                )

                object_evidence.setdefault(
                    f"gateway:{gw_name}",
                    [],
                ).append(f"References nonexistent GatewayClass '{gc_name}'")

                object_evidence.setdefault(
                    f"gatewayclass:{gc_name}",
                    [],
                ).append("GatewayClass not present in object graph")

                continue

            accepted, reason, message = self._accepted_condition(gc)

            if accepted is False:
                unaccepted.append(
                    (
                        gw_name,
                        gc_name,
                        reason or message,
                    )
                )

                object_evidence.setdefault(
                    f"gatewayclass:{gc_name}",
                    [],
                ).append(
                    "GatewayClass Accepted=False" + (f" ({reason})" if reason else "")
                )

            elif accepted is None:
                # Status absent after reconciliation commonly means
                # controller unavailable or not managing the class.
                controller = gc.get("spec", {}).get("controllerName", "")

                object_evidence.setdefault(
                    f"gatewayclass:{gc_name}",
                    [],
                ).append("GatewayClass has no Accepted condition")

                if controller:
                    object_evidence[f"gatewayclass:{gc_name}"].append(
                        f"controllerName={controller}"
                    )

        matching_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._event_matches(e)
        ]

        # Escalate only if we have:
        #
        #  - missing GatewayClass
        #  - explicit Accepted=False
        #  - reconciliation events indicating failure
        #
        if not missing and not unaccepted and not matching_events:
            return None

        return {
            "missing": missing,
            "unaccepted": unaccepted,
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
            raise ValueError("GatewayClassUnavailable explain() called without match")

        evidence: list[str] = []

        for gateway, gc in candidate["missing"]:
            evidence.append(
                f"Gateway '{gateway}' references missing GatewayClass '{gc}'"
            )

        for _gateway, gc, detail in candidate["unaccepted"]:
            if detail:
                evidence.append(f"GatewayClass '{gc}' is not accepted ({detail})")
            else:
                evidence.append(f"GatewayClass '{gc}' is not accepted")

        for event in candidate["events"][:3]:
            msg = self._message(event)
            if msg:
                evidence.append(msg)

        chain = CausalChain(
            causes=[
                Cause(
                    code="GATEWAY_REFERENCES_GATEWAYCLASS",
                    message="Gateway references a GatewayClass",
                    role="runtime_context",
                ),
                Cause(
                    code="GATEWAYCLASS_UNAVAILABLE",
                    message="GatewayClass is unavailable or not accepted",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="GATEWAY_CANNOT_BE_PROGRAMMED",
                    message="Gateway controller cannot program the Gateway",
                    role="workload_symptom",
                ),
            ]
        )

        confidence = 0.90

        if candidate["missing"] or candidate["unaccepted"]:
            confidence = 0.99

        return {
            "rule": self.name,
            "root_cause": (
                "Gateway references an unavailable or unaccepted GatewayClass"
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
                "Referenced GatewayClass does not exist",
                "GatewayClass controller is not installed",
                "GatewayClass controller is unavailable",
                "GatewayClass was rejected by its controller",
                "Incorrect gatewayClassName specified in the Gateway",
                "Gateway controller implementation is not managing this GatewayClass",
            ],
            "suggested_checks": [
                "kubectl get gatewayclass",
                "kubectl describe gatewayclass <gatewayclass-name>",
                "kubectl get gateways.gateway.networking.k8s.io -A",
                "kubectl describe gateway <gateway-name>",
                "kubectl get gatewayclass -o yaml",
                "kubectl get gateway -A -o yaml",
                "Verify the GatewayClass controller is installed and running",
                "Check controller logs for GatewayClass reconciliation failures",
            ],
        }
