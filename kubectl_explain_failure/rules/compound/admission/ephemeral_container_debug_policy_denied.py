from __future__ import annotations

import re
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class EphemeralContainerDebugPolicyDeniedRule(FailureRule):
    """
    Detects ephemeral-container debugging attempts that were blocked by
    admission control or authorization policy.

    Real-world interpretation:
    - an operator executes kubectl debug
    - Kubernetes attempts to update the pods/ephemeralcontainers subresource
    - admission, Pod Security, Gatekeeper, Kyverno, Kubewarden,
      ValidatingAdmissionPolicy, custom webhook, or RBAC denies the request
    - no debug container is created

    This rule explains why debugging failed, not why the workload failed.
    """

    name = "EphemeralContainerDebugPolicyDenied"
    category = "Compound"
    priority = 88
    deterministic = True

    blocks = [
        "AdmissionWebhookDenied",
        "RBACForbidden",
    ]

    requires = {
        "context": [],
    }

    supported_phases = {
        "Pending",
        "Running",
        "Succeeded",
        "Failed",
        "Unknown",
    }

    DEBUG_MARKERS = (
        "pods/ephemeralcontainers",
        "ephemeralcontainers",
        "ephemeral container",
        "ephemeralcontainer",
        "kubectl debug",
        "debug container",
        "debugger container",
    )

    DENIAL_MARKERS = (
        "forbidden",
        "denied",
        "denied the request",
        "not authorized",
        "unauthorized",
        "cannot patch",
        "cannot update",
        "is forbidden",
        "failed admission",
        "admission denied",
        "request denied",
        "validation failure",
        "validation error",
    )

    EPHEMERAL_DENIAL_MARKERS = (
        "pods/ephemeralcontainers is forbidden",
        'cannot patch resource "pods/ephemeralcontainers"',
        'cannot update resource "pods/ephemeralcontainers"',
        "ephemeralcontainers is forbidden",
        "ephemeral container may not be added",
        "ephemeral containers may not be added",
        "ephemeral containers are disabled",
        "ephemeral container injection denied",
        "debug container denied",
    )

    POLICY_MARKERS = (
        "podsecurity",
        "pod security",
        "restricted",
        "baseline",
        "gatekeeper",
        "opa",
        "kyverno",
        "kubewarden",
        "validatingadmissionpolicy",
        "validating admission policy",
        "validating webhook",
        "admission webhook",
        "policy",
    )

    RBAC_MARKERS = (
        "cannot patch resource",
        "cannot update resource",
        "cannot create resource",
        "user ",
        "system:serviceaccount",
        "rbac",
    )

    NON_DEBUG_EXCLUSIONS = (
        "configmaps",
        "secrets",
        "persistentvolumeclaims",
        "persistentvolumes",
        "serviceaccounts",
        "roles",
        "rolebindings",
        "clusterroles",
        "clusterrolebindings",
        "leases",
        "events",
    )

    WEBHOOK_RE = re.compile(
        r'admission webhook\s+"([^"]+)"',
        re.IGNORECASE,
    )

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _text(self, event: dict[str, Any]) -> str:
        return f"{self._reason(event)} {self._message(event)}"

    def _event_targets_pod(
        self,
        event: dict[str, Any],
        pod_name: str,
    ) -> bool:
        involved = event.get("involvedObject", {})

        if isinstance(involved, dict):
            if (
                str(involved.get("kind", "")).lower() == "pod"
                and involved.get("name") == pod_name
            ):
                return True

        return pod_name.lower() in self._message(event)

    def _contains_debug_context(self, text: str) -> bool:
        return any(marker in text for marker in self.DEBUG_MARKERS)

    def _contains_denial(self, text: str) -> bool:
        return any(marker in text for marker in self.DENIAL_MARKERS)

    def _is_unrelated_forbidden(self, text: str) -> bool:
        if self._contains_debug_context(text):
            return False

        return any(marker in text for marker in self.NON_DEBUG_EXCLUSIONS)

    def _classify_source(self, text: str) -> str:
        if (
            "podsecurity" in text
            or "pod security" in text
            or "restricted" in text
            or "baseline" in text
        ):
            return "PodSecurityAdmission"

        if "gatekeeper" in text or "opa" in text:
            return "Gatekeeper"

        if "kyverno" in text:
            return "Kyverno"

        if "kubewarden" in text:
            return "Kubewarden"

        if "validating admission policy" in text or "validatingadmissionpolicy" in text:
            return "ValidatingAdmissionPolicy"

        if any(marker in text for marker in self.RBAC_MARKERS):
            if "pods/ephemeralcontainers" in text:
                return "RBAC"

        if "admission webhook" in text:
            return "AdmissionWebhook"

        return "Policy"

    def _extract_webhook(self, text: str) -> str | None:
        match = self.WEBHOOK_RE.search(text)
        if match:
            return match.group(1)
        return None

    def _is_ephemeral_debug_denial(
        self,
        event: dict[str, Any],
        pod_name: str,
    ) -> bool:
        if not self._event_targets_pod(event, pod_name):
            return False

        text = self._text(event)

        if self._is_unrelated_forbidden(text):
            return False

        if any(marker in text for marker in self.EPHEMERAL_DENIAL_MARKERS):
            return True

        if self._contains_debug_context(text) and self._contains_denial(text):
            return True

        return False

    def _matching_event(
        self,
        pod: dict[str, Any],
        events,
    ) -> dict[str, Any] | None:
        pod_name = pod.get("metadata", {}).get("name", "")

        if not pod_name:
            return None

        for event in events or []:
            if self._is_ephemeral_debug_denial(
                event,
                pod_name,
            ):
                return event

        return None

    def matches(self, pod, events, context) -> bool:
        return self._matching_event(pod, events) is not None

    def explain(self, pod, events, context):
        event = self._matching_event(pod, events)

        if event is None:
            raise ValueError(
                "EphemeralContainerDebugPolicyDenied explain() called without match"
            )

        metadata = pod.get("metadata", {})

        pod_name = metadata.get(
            "name",
            "<unknown>",
        )

        namespace = metadata.get(
            "namespace",
            "default",
        )

        reason = str(event.get("reason", "Unknown"))

        message = str(event.get("message", "")).strip()

        text = self._text(event)

        source = self._classify_source(text)

        webhook_name = self._extract_webhook(message)

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEBUG_SESSION_REQUESTED",
                    message=(
                        "An operator attempted to add an " "ephemeral debug container"
                    ),
                    role="operator_action",
                ),
                Cause(
                    code="DEBUG_REQUEST_REJECTED",
                    message=(
                        "Authorization or admission policy "
                        "rejected the pods/ephemeralcontainers update"
                    ),
                    role="policy_root",
                    blocking=True,
                ),
                Cause(
                    code="DEBUG_CONTAINER_NOT_CREATED",
                    message=(
                        "The ephemeral container was never admitted " "into the pod"
                    ),
                    role="platform_effect",
                ),
            ]
        )

        likely_causes = []

        if source == "PodSecurityAdmission":
            likely_causes.append(
                "Pod Security Admission policy forbids ephemeral container injection"
            )

        elif source == "Gatekeeper":
            likely_causes.append("OPA Gatekeeper constraint denied the debug request")

        elif source == "Kyverno":
            likely_causes.append("Kyverno validation policy denied the debug request")

        elif source == "Kubewarden":
            likely_causes.append("Kubewarden policy denied the debug request")

        elif source == "RBAC":
            likely_causes.append(
                "Caller lacks permission to update pods/ephemeralcontainers"
            )

        elif source == "AdmissionWebhook":
            likely_causes.append("A validating admission webhook rejected the request")

        likely_causes.extend(
            [
                "Cluster security controls prohibit ephemeral debugging in production",
                "Organizational policy blocks runtime debug container injection",
            ]
        )

        evidence = [
            f"Event reason: {reason}",
            "Request attempted to inject an ephemeral debug container",
            f"Denial source classified as {source}",
        ]

        if webhook_name:
            evidence.append(f"Admission webhook {webhook_name} rejected the request")

        if message:
            evidence.append(message)

        return {
            "root_cause": (
                "Ephemeral container debugging was blocked "
                "by admission policy or authorization controls"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{namespace}/{pod_name}": [
                    "Ephemeral debug container could not be injected",
                    f"Denial source={source}",
                    *([message] if message else []),
                ]
            },
            "likely_causes": likely_causes,
            "suggested_checks": [
                (
                    f"kubectl auth can-i patch "
                    f"pods/ephemeralcontainers -n {namespace}"
                ),
                (f"kubectl describe pod " f"{pod_name} -n {namespace}"),
                "Review Pod Security Admission configuration",
                "Inspect Gatekeeper constraints and constraint templates",
                "Inspect Kyverno ClusterPolicy and Policy resources",
                "Inspect ValidatingAdmissionPolicy resources",
                "Review validating admission webhooks",
                "Check Kubernetes API audit logs for the rejected request",
            ],
        }
