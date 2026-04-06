import re

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class SecretNotFoundRule(FailureRule):
    """
    Detects Pod startup failures caused by a referenced Secret that does not exist.

    Real-world behavior:
    - missing Secrets commonly surface as CreateContainerConfigError when a
      container env/envFrom secret reference cannot be resolved
    - they also surface as FailedMount when a secret-backed or projected volume
      cannot be prepared
    - imagePullSecret failures are handled by dedicated image-pull rules and are
      intentionally excluded here
    """

    name = "SecretNotFound"
    category = "Secret"
    priority = 58
    deterministic = True
    phases = ["Pending", "Running"]
    container_states = ["waiting"]
    requires = {
        "context": ["timeline"],
        "objects": ["secret"],  # presence-based contract: graph may be empty
    }
    blocks = [
        "ContainerCreateConfigError",
        "FailedMount",
    ]

    SECRET_NOT_FOUND_RE = re.compile(
        r'secret "(?P<name>[^"]+)" not found',
        re.IGNORECASE,
    )
    SECRET_LOOKUP_NOT_FOUND_RE = re.compile(
        r"couldn't get secret (?:(?:[^/\s]+)/)?(?P<name>[^,\s]+), not found",
        re.IGNORECASE,
    )
    IMAGE_PULL_MARKERS = (
        "failedtoretrieveimagepullsecret",
        "imagepullsecret",
        "image pull secret",
        "errimagepull",
        "imagepullbackoff",
    )

    def _extract_missing_secret_name(self, message: str) -> str | None:
        for pattern in (self.SECRET_NOT_FOUND_RE, self.SECRET_LOOKUP_NOT_FOUND_RE):
            match = pattern.search(message)
            if match:
                return str(match.group("name"))
        return None

    def _collect_secret_references(self, pod: dict) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}
        spec = pod.get("spec", {}) or {}

        def add(name: str | None, source: str, optional: bool = False) -> None:
            if not name or optional:
                return
            refs.setdefault(str(name), [])
            if source not in refs[str(name)]:
                refs[str(name)].append(source)

        for volume in spec.get("volumes", []) or []:
            volume_name = volume.get("name", "<volume>")

            secret_volume = volume.get("secret") or {}
            add(
                secret_volume.get("secretName"),
                f"Referenced by secret volume '{volume_name}'",
                bool(secret_volume.get("optional")),
            )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_secret = source.get("secret") or {}
                add(
                    projected_secret.get("name"),
                    f"Referenced by projected volume '{volume_name}'",
                    bool(projected_secret.get("optional")),
                )

        for container_group in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = container.get("name", "<container>")

                for env in container.get("env", []) or []:
                    secret_key_ref = (env.get("valueFrom") or {}).get(
                        "secretKeyRef"
                    ) or {}
                    add(
                        secret_key_ref.get("name"),
                        f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        bool(secret_key_ref.get("optional")),
                    )

                for env_from in container.get("envFrom", []) or []:
                    secret_ref = env_from.get("secretRef") or {}
                    add(
                        secret_ref.get("name"),
                        f"Referenced by envFrom in container '{container_name}'",
                        bool(secret_ref.get("optional")),
                    )

        return refs

    def _relevant_failures(
        self,
        pod: dict,
        events: list[dict],
        context: dict,
    ) -> list[tuple[dict, str]]:
        timeline = context.get("timeline")
        if not timeline:
            return []

        has_kubelet_surface = timeline_has_pattern(
            timeline,
            [{"reason": "CreateContainerConfigError"}],
        ) or timeline_has_pattern(
            timeline,
            [{"reason": "FailedMount"}],
        )
        if not has_kubelet_surface:
            return []

        refs = self._collect_secret_references(pod)
        if not refs:
            return []

        relevant: list[tuple[dict, str]] = []
        for event in events:
            reason = str(event.get("reason", ""))
            msg = str(event.get("message", ""))
            lowered = f"{reason} {msg}".lower()

            if any(marker in lowered for marker in self.IMAGE_PULL_MARKERS):
                continue

            missing_name = self._extract_missing_secret_name(msg)
            if not missing_name:
                continue

            if missing_name not in refs:
                continue

            relevant.append((event, missing_name))

        return relevant

    def matches(self, pod, events, context) -> bool:
        return bool(self._relevant_failures(pod, events, context))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        relevant = self._relevant_failures(pod, events, context)
        if not relevant:
            raise ValueError("SecretNotFound explain() called without match")

        references = self._collect_secret_references(pod)
        last_event, missing_name = relevant[-1]
        reasons_seen = []
        for event, _ in relevant:
            reason = str(event.get("reason", ""))
            if reason and reason not in reasons_seen:
                reasons_seen.append(reason)

        root_cause_msg = "Referenced Secret does not exist"

        chain = CausalChain(
            causes=[
                Cause(
                    code="SECRET_REFERENCE",
                    message=f"Pod references Secret '{missing_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="SECRET_NOT_FOUND",
                    message=f"Secret '{missing_name}' not found",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SECRET_DEPENDENCY_BLOCKS_STARTUP",
                    message="Kubelet cannot resolve secret-backed configuration required to start the Pod",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [f"Secret '{missing_name}' not found"]
        for reason in reasons_seen:
            evidence.append(f"Event: {reason}")
        if len(reasons_seen) > 1:
            evidence.append(
                "Missing Secret surfaces across multiple kubelet startup checks"
            )

        object_evidence = {
            f"secret:{missing_name}": [
                "Secret not found in Pod namespace",
                *references.get(missing_name, []),
            ]
        }

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Secret name typo in an env, envFrom, or volume reference",
                "Secret was deleted or not yet created in the Pod namespace",
                "Secret exists in a different namespace than the Pod",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get secret",
                f"kubectl get secret {missing_name}",
            ],
        }
