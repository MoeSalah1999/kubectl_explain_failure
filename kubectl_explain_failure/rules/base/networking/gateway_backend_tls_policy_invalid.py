from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class GatewayBackendTLSPolicyInvalidRule(FailureRule):
    """
    Detects an invalid Gateway API BackendTLSPolicy.

    Real-world behavior:
    - BackendTLSPolicy is used to configure TLS validation when a Gateway
      connects to HTTPS/TLS backends.
    - Controllers reject BackendTLSPolicies that contain invalid references,
      malformed validation configuration, unsupported TLS settings,
      missing CA references, or invalid targetRefs.
    - When invalid, Gateway API controllers typically publish:
          Accepted=False
          ResolvedRefs=False
      on BackendTLSPolicy status conditions.
    - Traffic may continue failing even though:
          * Gateway exists
          * HTTPRoute is accepted
          * Backend Service exists
      because backend TLS validation cannot be programmed.

    Common causes:
    - targetRef points to unsupported object kind
    - targetRef points to non-existent Service
    - caCertificateRefs reference missing ConfigMaps/Secrets
    - cross-namespace CA references without ReferenceGrant
    - malformed hostname / subjectAltNames configuration
    - controller-specific TLS validation constraints

    Exclusions:
    - Backend Service unavailable
    - EndpointSlice failures
    - Route attachment failures
    - Gateway listener failures
    - Upstream TLS handshake failures after successful programming
    """

    name = "GatewayBackendTLSPolicyInvalid"
    category = "Networking"
    severity = "High"
    priority = 80
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "backendtlspolicy",
            "service",
            "referencegrant",
            "configmap",
            "secret",
            "gateway",
            "httproute",
        ],
    }

    WINDOW_MINUTES = 30

    INVALID_REASONS = {
        "invalid",
        "invalidconfiguration",
        "invalidtlsconfiguration",
        "invalidcacertificateref",
        "invalidtargetref",
        "targetnotfound",
        "backendnotfound",
        "unsupportedvalue",
        "unsupportedkind",
        "refnotpermitted",
        "referencenotpermitted",
        "resolvedrefs",
    }

    STATUS_TYPES = {
        "Accepted",
        "ResolvedRefs",
    }

    EVENT_MARKERS = (
        "backendtlspolicy",
        "invalid",
        "tls",
        "certificate",
        "cacertificateref",
        "targetref",
        "resolvedrefs",
        "accepted",
        "not permitted",
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

    def _find_candidate_policies(
        self,
        context: dict[str, Any],
        pod: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Prefer policies in the workload namespace.

        This mirrors the approach used by many existing rules
        until relation graph support becomes authoritative.
        """
        pod_ns = pod.get("metadata", {}).get("namespace")

        policies = []

        for policy in (
            context.get("objects", {})
            .get(
                "backendtlspolicy",
                {},
            )
            .values()
        ):
            if not isinstance(policy, dict):
                continue

            if self._object_namespace(policy) == pod_ns:
                policies.append(policy)

        return policies

    def _invalid_condition(
        self,
        policy: dict[str, Any],
    ) -> dict[str, Any] | None:
        status = policy.get("status", {}) or {}

        for condition in status.get("conditions", []) or []:

            cond_type = str(condition.get("type") or "")
            cond_status = str(condition.get("status") or "").lower()
            cond_reason = str(condition.get("reason") or "").lower()

            if cond_type not in self.STATUS_TYPES:
                continue

            if cond_status != "false":
                continue

            if (
                cond_reason in self.INVALID_REASONS
                or "invalid" in cond_reason
                or "notfound" in cond_reason
                or "permitted" in cond_reason
            ):
                return condition

        return None

    def _target_ref(
        self,
        policy: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        target = policy.get("spec", {}).get("targetRef", {})

        if not isinstance(target, dict):
            return None, None

        return (
            str(target.get("kind") or ""),
            str(target.get("name") or ""),
        )

    def _recent_policy_event(
        self,
        timeline: Timeline,
        policy_name: str,
    ) -> dict[str, Any] | None:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        for event in reversed(recent):

            message = self._message(event).lower()

            if policy_name.lower() not in message:
                continue

            if any(marker in message for marker in self.EVENT_MARKERS):
                return event

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        policies = self._find_candidate_policies(
            context,
            pod,
        )

        for policy in policies:

            condition = self._invalid_condition(policy)

            if not condition:
                continue

            policy_name = self._object_name(policy)
            namespace = self._object_namespace(policy)

            reason = str(condition.get("reason") or "")
            message = str(condition.get("message") or "")

            target_kind, target_name = self._target_ref(policy)

            event = self._recent_policy_event(
                timeline,
                policy_name,
            )

            object_evidence = {
                f"backendtlspolicy:{policy_name}": [
                    f"{condition.get('type')}=False " f"({reason}: {message})"
                ]
            }

            if target_kind and target_name:
                object_evidence[f"{target_kind.lower()}:{target_name}"] = [
                    "Referenced by invalid BackendTLSPolicy"
                ]

            return {
                "policy_name": policy_name,
                "namespace": namespace,
                "reason": reason,
                "message": message,
                "target_kind": target_kind,
                "target_name": target_name,
                "event": event,
                "condition_type": str(condition.get("type") or ""),
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
            raise ValueError(
                "GatewayBackendTLSPolicyInvalid " "requires Timeline context"
            )

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "GatewayBackendTLSPolicyInvalid " "explain() called without match"
            )

        policy_name = candidate["policy_name"]
        namespace = candidate["namespace"]

        target_kind = candidate["target_kind"]
        target_name = candidate["target_name"]

        reason = candidate["reason"]
        message = candidate["message"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="BACKEND_TLS_POLICY_CONFIGURED",
                    message=(
                        "Gateway relies on BackendTLSPolicy "
                        "to validate TLS connections to upstream backends"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="BACKEND_TLS_POLICY_INVALID",
                    message=(
                        "Gateway controller rejected the "
                        "BackendTLSPolicy configuration"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="BACKEND_TLS_CONFIGURATION_NOT_PROGRAMMED",
                    message=(
                        "Backend TLS validation cannot be "
                        "applied to upstream traffic"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"BackendTLSPolicy {namespace}/{policy_name} "
                "contains an invalid configuration"
            ),
            (f"Controller reported " f"{candidate['condition_type']}=False"),
            (f"Reason: {reason}"),
        ]

        if message:
            evidence.append(f"Controller message: {message}")

        if target_kind and target_name:
            evidence.append(f"Policy targets {target_kind} {target_name}")

        if candidate["event"]:
            evidence.append(
                f"Recent policy event: " f"{self._message(candidate['event'])}"
            )

        return {
            "rule": self.name,
            "root_cause": (
                "BackendTLSPolicy was rejected by the " "Gateway controller"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": candidate["object_evidence"],
            "likely_causes": [
                "targetRef points to a non-existent Service",
                "targetRef references an unsupported resource kind",
                "caCertificateRefs reference a missing ConfigMap or Secret",
                "Cross-namespace certificate references require a ReferenceGrant",
                "BackendTLSPolicy contains unsupported TLS validation settings",
                "Hostname or subjectAltNames validation configuration is invalid",
                "Controller-specific BackendTLSPolicy validation failed",
            ],
            "suggested_checks": [
                (
                    f"kubectl get backendtlspolicy "
                    f"{policy_name} -n {namespace} -o yaml"
                ),
                (f"kubectl describe backendtlspolicy " f"{policy_name} -n {namespace}"),
                (
                    "Inspect status.conditions for "
                    "Accepted=False or ResolvedRefs=False"
                ),
                ("Verify targetRef points to an existing Service"),
                ("Verify all caCertificateRefs exist " "and are readable"),
                (
                    "Verify ReferenceGrant resources for any "
                    "cross-namespace certificate references"
                ),
                (
                    "Check Gateway controller logs for "
                    "BackendTLSPolicy validation errors"
                ),
            ],
        }
