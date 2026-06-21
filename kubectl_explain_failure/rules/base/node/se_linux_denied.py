from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SELinuxDeniedRule(FailureRule):
    """
    Detects workload failures caused by SELinux enforcement.

    This rule only fires when Kubernetes, kubelet,
    CRI-O, containerd, or the kernel reports evidence
    that SELinux denied an operation.

    It intentionally avoids matching generic
    permission failures.
    """

    name = "SELinuxDenied"

    category = "Node"
    severity = "High"

    priority = 68

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

    SELINUX_KEYWORDS = (
        "selinux",
        "avc:",
        "avc denied",
        "security_context_t",
        "container_t",
        "container_runtime_t",
    )

    DENIAL_PATTERNS = (
        "avc: denied",
        "selinux is preventing",
        "permission denied by selinux",
        "selinux denied",
        "selinux denial",
        "failed selinux context",
        "invalid selinux label",
        "mismatched selinux label",
        "failed to relabel",
        "relabel failed",
        "error setting selinux label",
        "operation not permitted by selinux",
        "mount denied",
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

    def _event_indicates_selinux_denial(
        self,
        event: dict[str, Any],
    ) -> bool:
        reason = str(event.get("reason", "")).lower()

        message = str(event.get("message", "")).lower()

        combined = f"{reason} {message}"

        if any(pattern in combined for pattern in self.DENIAL_PATTERNS):
            return True

        if "selinux" in combined and "denied" in combined:
            return True

        if "avc:" in combined and "denied" in combined:
            return True

        return False

    def _container_status_indicates_denial(
        self,
        pod: dict[str, Any],
    ) -> bool:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []

        for status in statuses:
            state = status.get("state", {}) or {}

            waiting = state.get("waiting")
            terminated = state.get("terminated")

            for candidate in (waiting, terminated):
                if not isinstance(candidate, dict):
                    continue

                reason = str(candidate.get("reason", "")).lower()

                message = str(candidate.get("message", "")).lower()

                combined = f"{reason} {message}"

                if self._selinux_denial_text(combined):
                    return True

        return False

    def _selinux_denial_text(
        self,
        text: str,
    ) -> bool:
        if any(pattern in text for pattern in self.DENIAL_PATTERNS):
            return True

        if "selinux" in text and (
            "denied" in text or "relabel" in text or "label" in text
        ):
            return True

        if "avc:" in text and "denied" in text:
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
            if self._event_indicates_selinux_denial(event):
                return True

        return self._container_status_indicates_denial(pod)

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
            if self._event_indicates_selinux_denial(event):
                message = event.get("message")
                if message:
                    evidence.append(str(message))

        if not evidence:
            evidence.append("SELinux denied a container operation")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SELINUX_ACCESS_DENIED",
                    message=("SELinux policy blocked " "a required operation"),
                    role="security_policy",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_STARTUP_BLOCKED",
                    message=(
                        "Container runtime could not " "complete the requested action"
                    ),
                    role="runtime",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": ("SELinux policy denied a required " "container operation"),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": evidence,
            },
            "likely_causes": [
                "Container attempted an operation not permitted by SELinux policy",
                "Volume relabeling failed",
                "SELinux context does not match node policy",
                "HostPath or mounted volume has incompatible labels",
                "Container runtime generated an invalid SELinux label",
                "Custom SELinux policy is missing required permissions",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Inspect kubelet events for SELinux denials",
                "Review audit.log for AVC denials",
                "Run ausearch -m avc on the affected node",
                "Verify pod securityContext.seLinuxOptions",
                "Check volume label compatibility",
                "Review CRI-O/containerd logs",
            ],
        }
