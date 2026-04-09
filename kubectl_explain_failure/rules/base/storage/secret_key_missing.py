import re

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class SecretKeyMissingRule(FailureRule):
    """
    Detects Pod startup failures caused by a referenced Secret key that does not
    exist, even though the Secret object itself exists.

    Real-world behavior:
    - env[].valueFrom.secretKeyRef failures commonly surface as
      CreateContainerConfigError with "couldn't find key ... in Secret ..."
    - secret volume item failures surface as FailedMount with
      "references non-existent secret key: ..."
    - optional Secret key references are intentionally excluded
    """

    name = "SecretKeyMissing"
    category = "Secret"
    priority = 59
    deterministic = True
    phases = ["Pending", "Running"]
    container_states = ["waiting"]
    requires = {
        "context": ["timeline"],
        "objects": ["secret"],
    }
    blocks = [
        "ContainerCreateConfigError",
        "FailedMount",
    ]

    KEY_IN_SECRET_RE = re.compile(
        r'couldn\'t find key "?([^"\s]+)"? in Secret (?:(?:[^/\s]+)/)?([^\s",]+)',
        re.IGNORECASE,
    )
    NONEXISTENT_KEY_RE = re.compile(
        r"references non-existent secret key:\s*([^\s\",]+)",
        re.IGNORECASE,
    )
    VOLUME_NAME_RE = re.compile(r'volume "([^"]+)"', re.IGNORECASE)

    def _collect_references(self, pod: dict) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        spec = pod.get("spec", {}) or {}

        for container_group in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = container.get("name", "<container>")
                for env in container.get("env", []) or []:
                    secret_key_ref = (env.get("valueFrom") or {}).get(
                        "secretKeyRef"
                    ) or {}
                    if secret_key_ref.get("optional"):
                        continue
                    name = secret_key_ref.get("name")
                    key = secret_key_ref.get("key")
                    if not name or not key:
                        continue
                    refs.append(
                        {
                            "secret": str(name),
                            "key": str(key),
                            "surface": f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        }
                    )

        for volume in spec.get("volumes", []) or []:
            volume_name = volume.get("name", "<volume>")

            secret = volume.get("secret") or {}
            secret_name = secret.get("secretName")
            if secret_name and not secret.get("optional"):
                for item in secret.get("items", []) or []:
                    key = item.get("key")
                    if not key:
                        continue
                    refs.append(
                        {
                            "secret": str(secret_name),
                            "key": str(key),
                            "surface": f"Referenced by secret volume '{volume_name}'",
                            "volume": str(volume_name),
                        }
                    )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_secret = source.get("secret") or {}
                secret_name = projected_secret.get("name")
                if not secret_name or projected_secret.get("optional"):
                    continue
                for item in projected_secret.get("items", []) or []:
                    key = item.get("key")
                    if not key:
                        continue
                    refs.append(
                        {
                            "secret": str(secret_name),
                            "key": str(key),
                            "surface": f"Referenced by projected volume '{volume_name}'",
                            "volume": str(volume_name),
                        }
                    )

        return refs

    def _secret_has_key(self, context: dict, secret_name: str, key: str) -> bool:
        secrets = context.get("objects", {}).get("secret", {}) or {}
        secret = secrets.get(secret_name)
        if not isinstance(secret, dict):
            return False

        data = secret.get("data", {}) or {}
        binary_data = secret.get("binaryData", {}) or {}
        string_data = secret.get("stringData", {}) or {}
        return key in data or key in binary_data or key in string_data

    def _available_keys(self, context: dict, secret_name: str) -> list[str]:
        secrets = context.get("objects", {}).get("secret", {}) or {}
        secret = secrets.get(secret_name)
        if not isinstance(secret, dict):
            return []

        data = secret.get("data", {}) or {}
        binary_data = secret.get("binaryData", {}) or {}
        string_data = secret.get("stringData", {}) or {}
        return sorted(
            {
                *(str(k) for k in data),
                *(str(k) for k in binary_data),
                *(str(k) for k in string_data),
            }
        )

    def _match_event(
        self,
        event: dict,
        refs: list[dict[str, str]],
        context: dict,
    ) -> tuple[str, str] | None:
        message = str(event.get("message", ""))

        key_in_secret = self.KEY_IN_SECRET_RE.search(message)
        if key_in_secret:
            key = str(key_in_secret.group(1))
            secret_name = str(key_in_secret.group(2))
            if self._secret_has_key(context, secret_name, key):
                return None
            for ref in refs:
                if ref["secret"] == secret_name and ref["key"] == key:
                    return secret_name, key

        nonexistent_key = self.NONEXISTENT_KEY_RE.search(message)
        if not nonexistent_key:
            return None

        key = str(nonexistent_key.group(1))
        volume_match = self.VOLUME_NAME_RE.search(message)
        volume_name = str(volume_match.group(1)) if volume_match else None

        candidates = [
            ref
            for ref in refs
            if ref["key"] == key
            and (volume_name is None or ref.get("volume") == volume_name)
        ]
        if len(candidates) != 1:
            return None

        secret_name = candidates[0]["secret"]
        if self._secret_has_key(context, secret_name, key):
            return None

        return secret_name, key

    def _relevant_failures(
        self, pod: dict, events: list[dict], context: dict
    ) -> list[tuple[dict, str, str]]:
        timeline = context.get("timeline")
        if not timeline:
            return []

        has_surface = timeline_has_pattern(
            timeline,
            [{"reason": "CreateContainerConfigError"}],
        ) or timeline_has_pattern(
            timeline,
            [{"reason": "FailedMount"}],
        )
        if not has_surface:
            return []

        refs = self._collect_references(pod)
        if not refs:
            return []

        relevant: list[tuple[dict, str, str]] = []
        for event in events:
            matched = self._match_event(event, refs, context)
            if matched is None:
                continue
            secret_name, key = matched
            relevant.append((event, secret_name, key))

        return relevant

    def matches(self, pod, events, context) -> bool:
        return bool(self._relevant_failures(pod, events, context))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        relevant = self._relevant_failures(pod, events, context)
        if not relevant:
            raise ValueError("SecretKeyMissing explain() called without match")

        refs = self._collect_references(pod)
        _last_event, secret_name, key = relevant[-1]

        reasons_seen: list[str] = []
        for event, _, _ in relevant:
            reason = str(event.get("reason", ""))
            if reason and reason not in reasons_seen:
                reasons_seen.append(reason)

        reference_surfaces = [
            ref["surface"]
            for ref in refs
            if ref["secret"] == secret_name and ref["key"] == key
        ]

        evidence = [f"Secret '{secret_name}' is missing required key '{key}'"]
        for reason in reasons_seen:
            evidence.append(f"Event: {reason}")
        if len(reasons_seen) > 1:
            evidence.append(
                "Missing Secret key surfaces across multiple kubelet startup checks"
            )

        available_keys = self._available_keys(context, secret_name)
        object_evidence = {
            f"secret:{secret_name}": [
                f"Required key '{key}' is absent",
                *reference_surfaces,
            ]
        }
        if available_keys:
            object_evidence[f"secret:{secret_name}"].append(
                "Available keys: " + ", ".join(available_keys)
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SECRET_KEY_REFERENCE",
                    message=f"Pod references key '{key}' from Secret '{secret_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="SECRET_KEY_NOT_FOUND",
                    message=f"Required key '{key}' does not exist in Secret '{secret_name}'",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SECRET_DEPENDENCY_BLOCKS_STARTUP",
                    message="Kubelet cannot resolve required Secret-backed configuration for startup",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Referenced Secret is missing a required key",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Secret key name typo in an env or volume item reference",
                "Secret was updated and no longer includes the expected key",
                "Workload manifest expects secret data that was never populated",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get secret {secret_name} -o yaml",
                "Review secretKeyRef and secret volume item keys in the Pod spec",
            ],
        }
