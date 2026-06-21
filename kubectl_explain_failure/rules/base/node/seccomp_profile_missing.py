from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class SeccompProfileMissingRule(FailureRule):
    """
    Detects Pods running without an effective seccomp profile.

    Real-world behavior:

    Kubernetes supports seccomp at both Pod and container scope.

    Secure workloads should use:

        seccompProfile:
          type: RuntimeDefault

    or

        seccompProfile:
          type: Localhost

    A workload is considered exposed when neither Pod nor container level
    seccomp configuration exists.

    Explicit Unconfined is treated as even stronger evidence.

    Exclusions:
    - Windows workloads
    - Pods already protected by RuntimeDefault
    - Pods already protected by Localhost profiles
    """

    name = "SeccompProfileMissing"

    category = "Node"
    severity = "Medium"

    priority = 61

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

    def _all_containers(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        spec = pod.get("spec", {}) or {}

        containers = list(spec.get("containers", []) or [])
        containers.extend(spec.get("initContainers", []) or [])
        containers.extend(spec.get("ephemeralContainers", []) or [])

        return [c for c in containers if isinstance(c, dict)]

    def _is_windows_pod(self, pod: dict[str, Any]) -> bool:
        spec = pod.get("spec", {}) or {}

        os_name = (spec.get("os", {}) or {}).get("name")

        if os_name == "windows":
            return True

        node_selector = spec.get("nodeSelector", {}) or {}

        return node_selector.get("kubernetes.io/os") == "windows"

    def _pod_seccomp(self, pod: dict[str, Any]) -> dict[str, Any] | None:
        return pod.get("spec", {}).get("securityContext", {}).get("seccompProfile")

    def _container_seccomp(
        self,
        container: dict[str, Any],
    ) -> dict[str, Any] | None:
        return container.get("securityContext", {}).get("seccompProfile")

    def _profile_type(
        self,
        profile: dict[str, Any] | None,
    ) -> str | None:
        if not isinstance(profile, dict):
            return None

        value = profile.get("type")

        if not value:
            return None

        return str(value)

    def _effective_profile_state(
        self,
        pod: dict[str, Any],
    ) -> tuple[str, list[str]]:
        """
        Returns:

            state:
                protected
                unconfined
                missing

            evidence
        """

        evidence: list[str] = []

        pod_profile = self._pod_seccomp(pod)

        pod_type = self._profile_type(pod_profile)

        if pod_type in {"RuntimeDefault", "Localhost"}:
            evidence.append(f"Pod seccomp profile configured as {pod_type}")
            return "protected", evidence

        if pod_type == "Unconfined":
            evidence.append("Pod seccomp profile explicitly set to Unconfined")
            return "unconfined", evidence

        containers = self._all_containers(pod)

        protected = False
        unconfined = False

        for container in containers:
            name = container.get("name", "<unknown>")

            profile_type = self._profile_type(self._container_seccomp(container))

            if profile_type in {"RuntimeDefault", "Localhost"}:
                protected = True
                evidence.append(f"Container {name} uses {profile_type}")

            elif profile_type == "Unconfined":
                unconfined = True
                evidence.append(f"Container {name} explicitly uses Unconfined")

        if protected:
            return "protected", evidence

        if unconfined:
            return "unconfined", evidence

        return "missing", evidence

    def matches(self, pod, events, context) -> bool:
        if self._is_windows_pod(pod):
            return False

        state, _ = self._effective_profile_state(pod)

        #
        # Explicit Unconfined is a security posture issue,
        # but not a runtime failure explanation.
        #
        if state == "unconfined":
            return False

        #
        # Missing seccomp profile alone is never sufficient.
        #
        if state != "missing":
            return False

        pod_status = pod.get("status", {}).get("phase", "")

        #
        # Only evaluate workloads that actually reached Running.
        #
        if pod_status != "Running":
            return False

        #
        # Require runtime evidence that seccomp admission
        # or runtime enforcement is involved.
        #
        for event in events:
            reason = str(event.get("reason", "")).lower()
            message = str(event.get("message", "")).lower()

            if "seccomp" in reason or "seccomp" in message:
                return True

            if "operation not permitted" in message and "syscall" in message:
                return True

            if "permission denied" in message and "seccomp" in message:
                return True

        #
        # No seccomp-related runtime signal.
        #
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        state, state_evidence = self._effective_profile_state(pod)

        node_name = pod.get("spec", {}).get("nodeName")

        object_evidence: dict[str, list[str]] = {}

        evidence = [
            f"Pod {namespace}/{pod_name} does not have an effective seccomp profile configured"
        ]

        evidence.extend(state_evidence)

        confidence = 0.96

        if state == "unconfined":
            confidence = 0.99
            evidence.append("Seccomp is explicitly disabled via Unconfined")
        else:
            evidence.append(
                "Neither Pod-level nor container-level seccompProfile configuration was found"
            )

        if node_name:
            object_evidence[f"node:{node_name}"] = [
                "Workload is scheduled on this node without an effective seccomp profile"
            ]

        object_evidence[f"pod:{pod_name}"] = [
            "No effective seccomp profile is configured"
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="SECCOMP_PROFILE_NOT_CONFIGURED",
                    message="The workload does not define an effective seccomp profile",
                    role="security_configuration",
                    blocking=False,
                ),
                Cause(
                    code="SYSTEM_CALL_FILTERING_REDUCED",
                    message="Container syscalls are not restricted by the recommended seccomp policy",
                    role="runtime_exposure",
                ),
            ]
        )

        likely_causes = [
            "The Pod spec omits securityContext.seccompProfile",
            "Containers inherit no explicit seccomp policy",
            "Cluster hardening standards were not applied during deployment",
        ]

        if state == "unconfined":
            likely_causes.insert(
                0,
                "The workload explicitly disables seccomp using Unconfined",
            )

        return {
            "rule": self.name,
            "root_cause": "Pod is running without a seccomp profile",
            "confidence": confidence,
            "blocking": False,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": [
                f"kubectl get pod {pod_name} -n {namespace} -o yaml",
                "Verify spec.securityContext.seccompProfile",
                "Verify container securityContext.seccompProfile settings",
                "Prefer seccompProfile.type=RuntimeDefault for general workloads",
                "Use Localhost profiles when application-specific syscall filtering is required",
            ],
        }
