from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class AppArmorProfileMissingRule(FailureRule):
    """
    Detects failures caused by missing AppArmor profiles.

    Real-world behavior:

    This rule intentionally does NOT fire merely because
    AppArmor is absent.

    It only triggers when Kubernetes, kubelet, or the
    container runtime reports that a requested AppArmor
    profile could not be found or applied.
    """

    name = "AppArmorProfileMissing"

    category = "Node"
    severity = "Medium"

    priority = 63

    deterministic = True

    phases = [
        "Pending",
        "Running",
    ]

    requires = {
        "pod": True,
        "optional_objects": [
            "node",
        ],
    }

    APPARMOR_KEYWORDS = (
        "apparmor",
        "app armor",
    )

    MISSING_PROFILE_PATTERNS = (
        "profile not found",
        "failed to load profile",
        "unable to load profile",
        "cannot load profile",
        "could not load profile",
        "failed to apply apparmor profile",
        "unable to apply apparmor profile",
        "invalid apparmor profile",
        "unknown apparmor profile",
        "apparmor parser error",
        "failed to generate apparmor spec",
        "failed to create apparmor profile",
        "failed to enforce apparmor profile",
    )

    def _is_windows_pod(
        self,
        pod: dict[str, Any],
    ) -> bool:
        spec = pod.get("spec", {}) or {}

        os_name = (spec.get("os", {}) or {}).get("name")

        if os_name == "windows":
            return True

        node_selector = spec.get("nodeSelector", {}) or {}

        return node_selector.get("kubernetes.io/os") == "windows"

    def _event_mentions_missing_profile(
        self,
        event: dict[str, Any],
    ) -> bool:
        reason = str(event.get("reason", "")).lower()

        message = str(event.get("message", "")).lower()

        combined = f"{reason} {message}"

        if not any(keyword in combined for keyword in self.APPARMOR_KEYWORDS):
            return False

        return any(pattern in combined for pattern in self.MISSING_PROFILE_PATTERNS)

    def _container_waiting_reason(
        self,
        pod: dict[str, Any],
    ) -> bool:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []

        for status in statuses:
            waiting = status.get("state", {}).get("waiting")

            if not isinstance(waiting, dict):
                continue

            message = str(waiting.get("message", "")).lower()

            if "apparmor" in message and (
                "profile" in message
                or "permission denied" in message
                or "not found" in message
            ):
                return True

        return False

    def matches(
        self,
        pod,
        events,
        context,
    ) -> bool:
        if self._is_windows_pod(pod):
            return False

        for event in events:
            if self._event_mentions_missing_profile(event):
                return True

        return self._container_waiting_reason(pod)

    def explain(
        self,
        pod,
        events,
        context,
    ):
        metadata = pod.get("metadata", {}) or {}

        pod_name = metadata.get(
            "name",
            "<unknown>",
        )

        namespace = metadata.get(
            "namespace",
            "default",
        )

        evidence: list[str] = []

        for event in events:
            if self._event_mentions_missing_profile(event):
                message = event.get("message")
                if message:
                    evidence.append(str(message))

        if not evidence:
            evidence.append(
                "Container runtime reported AppArmor profile loading failure"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="APPARMOR_PROFILE_MISSING",
                    message=(
                        "Requested AppArmor profile " "could not be found or loaded"
                    ),
                    role="security_configuration",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_START_BLOCKED",
                    message=("Container runtime rejected " "container startup"),
                    role="runtime",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "Requested AppArmor profile is missing " "or cannot be loaded"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": evidence,
            },
            "likely_causes": [
                "Referenced AppArmor profile does not exist on the node",
                "Node AppArmor configuration differs from workload expectations",
                "AppArmor profile failed to load after node upgrade",
                "Profile name contains an invalid value",
                "Container runtime cannot apply the requested profile",
            ],
            "suggested_checks": [
                (f"kubectl describe pod {pod_name} " f"-n {namespace}"),
                "Inspect kubelet events for AppArmor errors",
                "Verify the requested AppArmor profile exists on the node",
                "Check /sys/kernel/security/apparmor",
                "Check aa-status on the affected node",
                "Review container runtime logs",
            ],
        }
