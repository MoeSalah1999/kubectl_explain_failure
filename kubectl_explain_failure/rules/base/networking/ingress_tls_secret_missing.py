from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class IngressTLSSecretMissingRule(FailureRule):
    """
    Detects an Ingress or Gateway API listener that references a TLS Secret
    which does not exist or cannot be resolved.

    Real-world behavior:
    - ingress.spec.tls[].secretName references a Secret that is absent
    - Gateway listener tls.certificateRefs references a Secret that is absent
    - ingress-nginx, Traefik, Envoy Gateway, Gateway API controllers emit
      reconciliation failures due to missing TLS Secret
    - cert-manager has not yet created the Secret
    - Secret exists in the wrong namespace
    - RBAC/controller configuration prevents loading the Secret

    Does NOT fire when:
    - TLS is intentionally not configured
    - No Secret reference exists
    - Certificate contents are invalid (different rule)
    """

    name = "IngressTLSSecretMissing"
    category = "Networking"
    severity = "High"
    priority = 83
    deterministic = True

    phases = ["Pending", "Running", "Succeeded", "Failed"]

    requires = {
        "pod": False,
        "context": ["timeline"],
        "optional_objects": [
            "ingress",
            "gateway",
            "httproute",
            "tlsroute",
            "secret",
        ],
    }

    WINDOW_MINUTES = 30

    EVENT_MARKERS = (
        "secret",
        "tls",
        "certificate",
        "certificateRef",
        "certificateref",
        "errorgettingtlssecret",
        "secretnotfound",
        "not found",
        "failed to fetch secret",
        "failed to load secret",
        "failed to get secret",
        "referenced secret",
        "does not exist",
        "unable to find secret",
        "error obtaining x509 certificate",
    )

    CONTROLLER_HINTS = (
        "ingress",
        "nginx",
        "traefik",
        "gateway",
        "gateway-api",
        "envoy",
        "contour",
        "haproxy",
    )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _event_text(self, event: dict[str, Any]) -> str:
        return (
            f"{self._reason(event)} "
            f"{self._message(event)} "
            f"{event.get('type','')}"
        ).lower()

    def _event_matches(self, event: dict[str, Any]) -> bool:
        text = self._event_text(event)

        if not any(h in text for h in self.CONTROLLER_HINTS):
            return False

        if "secret" not in text:
            return False

        return any(marker in text for marker in self.EVENT_MARKERS)

    def _secret_exists(
        self,
        context: dict[str, Any],
        namespace: str,
        name: str,
    ) -> bool:
        secrets = context.get("objects", {}).get("secret", {})

        for obj in secrets.values():
            if not isinstance(obj, dict):
                continue

            md = obj.get("metadata", {})
            if md.get("namespace", "default") == namespace and md.get("name") == name:
                return True

        return False

    def _collect_ingress_refs(
        self,
        context: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        refs = []

        for ing in context.get("objects", {}).get("ingress", {}).values():
            if not isinstance(ing, dict):
                continue

            md = ing.get("metadata", {})
            namespace = md.get("namespace", "default")
            ing_name = md.get("name", "<unknown>")

            for tls in ing.get("spec", {}).get("tls", []) or []:
                secret = tls.get("secretName")
                if secret:
                    refs.append(
                        (
                            namespace,
                            secret,
                            f"ingress:{ing_name}",
                        )
                    )

        return refs

    def _collect_gateway_refs(
        self,
        context: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        refs = []

        for gw in context.get("objects", {}).get("gateway", {}).values():
            if not isinstance(gw, dict):
                continue

            md = gw.get("metadata", {})
            namespace = md.get("namespace", "default")
            gw_name = md.get("name", "<unknown>")

            listeners = gw.get("spec", {}).get("listeners", []) or []

            for listener in listeners:
                tls = listener.get("tls") or {}

                for ref in tls.get("certificateRefs", []) or []:
                    if ref.get("kind", "Secret") == "Secret" and ref.get("name"):
                        refs.append(
                            (
                                namespace,
                                ref["name"],
                                f"gateway:{gw_name}",
                            )
                        )

        return refs

    def _candidate(self, context: dict[str, Any]) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        refs = self._collect_ingress_refs(context) + self._collect_gateway_refs(context)

        if not refs:
            return None

        missing = []

        object_evidence: dict[str, list[str]] = {}

        for namespace, secret_name, owner in refs:
            if self._secret_exists(context, namespace, secret_name):
                continue

            missing.append((namespace, secret_name, owner))

            object_evidence.setdefault(
                f"secret:{namespace}/{secret_name}",
                [],
            ).append("Referenced TLS Secret does not exist in object graph")

        matching_events = [
            e
            for e in timeline.events_within_window(self.WINDOW_MINUTES)
            if self._event_matches(e)
        ]

        if not missing and not matching_events:
            return None

        return {
            "missing": missing,
            "events": matching_events,
            "object_evidence": object_evidence,
        }

    def matches(self, pod, events, context) -> bool:
        return self._candidate(context) is not None

    def explain(self, pod, events, context):
        candidate = self._candidate(context)

        if candidate is None:
            raise ValueError("IngressTLSSecretMissing explain() called without match")

        chain = CausalChain(
            causes=[
                Cause(
                    code="TLS_SECRET_REFERENCE_PRESENT",
                    message="Ingress or Gateway references a TLS Secret",
                    role="runtime_context",
                ),
                Cause(
                    code="TLS_SECRET_MISSING",
                    message="Referenced TLS Secret cannot be found",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="TLS_CONFIGURATION_CANNOT_BE_ACTIVATED",
                    message="Controller cannot configure HTTPS listener",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = []

        for namespace, secret_name, owner in candidate["missing"]:
            evidence.append(
                f"{owner} references missing TLS Secret " f"{namespace}/{secret_name}"
            )

        for event in candidate["events"][:3]:
            evidence.append(self._message(event))

        return {
            "rule": self.name,
            "root_cause": (
                "Ingress/Gateway references a TLS Secret that does not exist"
            ),
            "confidence": (0.99 if candidate["missing"] else 0.94),
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "TLS Secret has not yet been created",
                "cert-manager failed to issue or populate the Secret",
                "Secret exists in another namespace",
                "Ingress or Gateway references the wrong Secret name",
                "TLS Secret was deleted after configuration",
                "Controller cannot resolve the referenced Secret",
            ],
            "suggested_checks": [
                "kubectl get ingress -A -o yaml",
                "kubectl get gateway -A -o yaml",
                "kubectl get secret -A",
                "kubectl describe ingress <name>",
                "kubectl describe gateway <name>",
                "kubectl describe secret <secret-name>",
                "kubectl get certificaterequest -A",
                "kubectl get certificate -A",
                "kubectl logs -n ingress-nginx deploy/ingress-nginx-controller --tail=100",
            ],
        }
