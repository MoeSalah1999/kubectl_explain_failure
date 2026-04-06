import re

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class InvalidConfigMapKeyRule(FailureRule):
    """
    Detects Pod startup failures caused by a referenced ConfigMap key that does
    not exist, even though the ConfigMap object itself exists.
    """

    name = "InvalidConfigMapKey"
    category = "ConfigMap"
    priority = 57
    deterministic = True
    phases = ["Pending", "Running"]
    container_states = ["waiting"]
    requires = {
        "context": ["timeline"],
        "objects": ["configmap"],
    }
    blocks = [
        "ContainerCreateConfigError",
        "FailedMount",
    ]

    KEY_IN_CONFIGMAP_RE = re.compile(
        r'couldn\'t find key "?([^"\s]+)"? in ConfigMap (?:(?:[^/\s]+)/)?([^\s",]+)',
        re.IGNORECASE,
    )
    NONEXISTENT_KEY_RE = re.compile(
        r"configmap references non-existent config key:\s*([^\s\",]+)",
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
                    config_key_ref = (env.get("valueFrom") or {}).get(
                        "configMapKeyRef"
                    ) or {}
                    if config_key_ref.get("optional"):
                        continue
                    name = config_key_ref.get("name")
                    key = config_key_ref.get("key")
                    if not name or not key:
                        continue
                    refs.append(
                        {
                            "configmap": str(name),
                            "key": str(key),
                            "surface": f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        }
                    )

        for volume in spec.get("volumes", []) or []:
            volume_name = volume.get("name", "<volume>")

            config_map = volume.get("configMap") or {}
            configmap_name = config_map.get("name")
            if configmap_name:
                for item in config_map.get("items", []) or []:
                    if item.get("optional"):
                        continue
                    key = item.get("key")
                    if not key:
                        continue
                    refs.append(
                        {
                            "configmap": str(configmap_name),
                            "key": str(key),
                            "surface": f"Referenced by configMap volume '{volume_name}'",
                            "volume": str(volume_name),
                        }
                    )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_configmap = source.get("configMap") or {}
                configmap_name = projected_configmap.get("name")
                if not configmap_name:
                    continue
                for item in projected_configmap.get("items", []) or []:
                    if item.get("optional"):
                        continue
                    key = item.get("key")
                    if not key:
                        continue
                    refs.append(
                        {
                            "configmap": str(configmap_name),
                            "key": str(key),
                            "surface": f"Referenced by projected volume '{volume_name}'",
                            "volume": str(volume_name),
                        }
                    )

        return refs

    def _configmap_has_key(self, context: dict, configmap_name: str, key: str) -> bool:
        configmaps = context.get("objects", {}).get("configmap", {}) or {}
        configmap = configmaps.get(configmap_name)
        if not isinstance(configmap, dict):
            return False

        data = configmap.get("data", {}) or {}
        binary_data = configmap.get("binaryData", {}) or {}
        return key in data or key in binary_data

    def _available_keys(self, context: dict, configmap_name: str) -> list[str]:
        configmaps = context.get("objects", {}).get("configmap", {}) or {}
        configmap = configmaps.get(configmap_name)
        if not isinstance(configmap, dict):
            return []

        data = configmap.get("data", {}) or {}
        binary_data = configmap.get("binaryData", {}) or {}
        return sorted({*(str(k) for k in data), *(str(k) for k in binary_data)})

    def _match_event(
        self,
        event: dict,
        refs: list[dict[str, str]],
        context: dict,
    ) -> tuple[str, str] | None:
        message = str(event.get("message", ""))

        key_in_cm = self.KEY_IN_CONFIGMAP_RE.search(message)
        if key_in_cm:
            key = str(key_in_cm.group(1))
            configmap_name = str(key_in_cm.group(2))
            if self._configmap_has_key(context, configmap_name, key):
                return None
            for ref in refs:
                if ref["configmap"] == configmap_name and ref["key"] == key:
                    return configmap_name, key

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

        configmap_name = candidates[0]["configmap"]
        if self._configmap_has_key(context, configmap_name, key):
            return None

        return configmap_name, key

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
            configmap_name, key = matched
            relevant.append((event, configmap_name, key))

        return relevant

    def matches(self, pod, events, context) -> bool:
        return bool(self._relevant_failures(pod, events, context))

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        relevant = self._relevant_failures(pod, events, context)
        if not relevant:
            raise ValueError("InvalidConfigMapKey explain() called without match")

        refs = self._collect_references(pod)
        last_event, configmap_name, key = relevant[-1]
        del last_event

        reasons_seen: list[str] = []
        for event, _, _ in relevant:
            reason = str(event.get("reason", ""))
            if reason and reason not in reasons_seen:
                reasons_seen.append(reason)

        reference_surfaces = [
            ref["surface"]
            for ref in refs
            if ref["configmap"] == configmap_name and ref["key"] == key
        ]

        evidence = [f"ConfigMap '{configmap_name}' is missing required key '{key}'"]
        for reason in reasons_seen:
            evidence.append(f"Event: {reason}")
        if len(reasons_seen) > 1:
            evidence.append(
                "Missing ConfigMap key surfaces across multiple kubelet startup checks"
            )

        available_keys = self._available_keys(context, configmap_name)
        object_evidence = {
            f"configmap:{configmap_name}": [
                f"Required key '{key}' is absent",
                *reference_surfaces,
            ]
        }
        if available_keys:
            object_evidence[f"configmap:{configmap_name}"].append(
                "Available keys: " + ", ".join(available_keys)
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIGMAP_KEY_REFERENCE",
                    message=f"Pod references key '{key}' from ConfigMap '{configmap_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="CONFIGMAP_KEY_NOT_FOUND",
                    message=f"Required key '{key}' does not exist in ConfigMap '{configmap_name}'",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="CONFIG_DEPENDENCY_BLOCKS_STARTUP",
                    message="Kubelet cannot resolve required ConfigMap-backed configuration for startup",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Referenced ConfigMap is missing a required key",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "ConfigMap key name typo in an env or volume item reference",
                "ConfigMap was updated and no longer includes the expected key",
                "Workload manifest expects configuration data that was never populated",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get configmap {configmap_name} -o yaml",
                "Review configMapKeyRef and configMap volume item keys in the Pod spec",
            ],
        }
