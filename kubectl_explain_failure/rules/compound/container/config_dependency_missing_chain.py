from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ConfigDependencyMissingChainRule(FailureRule):
    """
    Detects startup-blocking chains where a missing configuration dependency
    surfaces first and container startup remains blocked afterwards.
    """

    name = "ConfigDependencyMissingChain"
    category = "Compound"
    priority = 63
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    optional_objects = ["configmap", "secret"]
    blocks = [
        "ConfigMapNotFound",
        "SecretNotFound",
        "InvalidConfigMapKey",
        "ContainerCreateConfigError",
        "FailedMount",
    ]

    WINDOW_MINUTES = 20
    MAX_CHAIN_SPAN_SECONDS = 900
    CONFIGMAP_NOT_FOUND_RE = re.compile(
        r'configmap "(?P<name>[^"]+)" not found',
        re.IGNORECASE,
    )
    SECRET_NOT_FOUND_RE = re.compile(
        r'secret "(?P<name>[^"]+)" not found',
        re.IGNORECASE,
    )
    KEY_IN_CONFIGMAP_RE = re.compile(
        r'couldn\'t find key "?([^"\s]+)"? in ConfigMap (?:(?:[^/\s]+)/)?([^\s",]+)',
        re.IGNORECASE,
    )
    NONEXISTENT_KEY_RE = re.compile(
        r"configmap references non-existent config key:\s*([^\s\",]+)",
        re.IGNORECASE,
    )
    VOLUME_NAME_RE = re.compile(r'volume "([^"]+)"', re.IGNORECASE)
    START_SUCCESS_REASONS = {"Started", "Created", "Pulled"}
    STARTUP_BLOCK_REASONS = {"CreateContainerConfigError", "FailedMount"}
    CACHE_KEY = "_config_dependency_missing_chain_candidate"

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _collect_configmap_refs(self, pod: dict) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        spec = pod.get("spec", {}) or {}

        def add(
            name: str | None,
            surface: str,
            *,
            key: str | None = None,
            volume: str | None = None,
            optional: bool = False,
        ) -> None:
            if optional or not name:
                return
            refs.append(
                {
                    "kind": "ConfigMap",
                    "name": str(name),
                    **({"key": str(key)} if key else {}),
                    **({"volume": str(volume)} if volume else {}),
                    "surface": surface,
                }
            )

        for container_group in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = container.get("name", "<container>")

                for env in container.get("env", []) or []:
                    ref = (env.get("valueFrom") or {}).get("configMapKeyRef") or {}
                    add(
                        ref.get("name"),
                        f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        key=ref.get("key"),
                        optional=bool(ref.get("optional")),
                    )

                for env_from in container.get("envFrom", []) or []:
                    ref = env_from.get("configMapRef") or {}
                    add(
                        ref.get("name"),
                        f"Referenced by envFrom in container '{container_name}'",
                        optional=bool(ref.get("optional")),
                    )

        for volume in spec.get("volumes", []) or []:
            volume_name = volume.get("name", "<volume>")
            config_map = volume.get("configMap") or {}
            if config_map.get("name"):
                items = config_map.get("items", []) or []
                if items:
                    for item in items:
                        add(
                            config_map.get("name"),
                            f"Referenced by configMap volume '{volume_name}'",
                            key=item.get("key"),
                            volume=volume_name,
                            optional=bool(
                                item.get("optional") or config_map.get("optional")
                            ),
                        )
                else:
                    add(
                        config_map.get("name"),
                        f"Referenced by configMap volume '{volume_name}'",
                        volume=volume_name,
                        optional=bool(config_map.get("optional")),
                    )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_cm = source.get("configMap") or {}
                if projected_cm.get("name"):
                    items = projected_cm.get("items", []) or []
                    if items:
                        for item in items:
                            add(
                                projected_cm.get("name"),
                                f"Referenced by projected volume '{volume_name}'",
                                key=item.get("key"),
                                volume=volume_name,
                                optional=bool(
                                    item.get("optional") or projected_cm.get("optional")
                                ),
                            )
                    else:
                        add(
                            projected_cm.get("name"),
                            f"Referenced by projected volume '{volume_name}'",
                            volume=volume_name,
                            optional=bool(projected_cm.get("optional")),
                        )

        return refs

    def _collect_secret_refs(self, pod: dict) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        spec = pod.get("spec", {}) or {}

        def add(name: str | None, surface: str, *, optional: bool = False) -> None:
            if optional or not name:
                return
            refs.append(
                {
                    "kind": "Secret",
                    "name": str(name),
                    "surface": surface,
                }
            )

        for container_group in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = container.get("name", "<container>")

                for env in container.get("env", []) or []:
                    ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
                    add(
                        ref.get("name"),
                        f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        optional=bool(ref.get("optional")),
                    )

                for env_from in container.get("envFrom", []) or []:
                    ref = env_from.get("secretRef") or {}
                    add(
                        ref.get("name"),
                        f"Referenced by envFrom in container '{container_name}'",
                        optional=bool(ref.get("optional")),
                    )

        for volume in spec.get("volumes", []) or []:
            volume_name = volume.get("name", "<volume>")
            secret = volume.get("secret") or {}
            add(
                secret.get("secretName"),
                f"Referenced by secret volume '{volume_name}'",
                optional=bool(secret.get("optional")),
            )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_secret = source.get("secret") or {}
                add(
                    projected_secret.get("name"),
                    f"Referenced by projected volume '{volume_name}'",
                    optional=bool(projected_secret.get("optional")),
                )

        return refs

    def _configmap_available_keys(self, context: dict, name: str) -> list[str]:
        configmap = (context.get("objects", {}).get("configmap", {}) or {}).get(name)
        if not isinstance(configmap, dict):
            return []
        data = configmap.get("data", {}) or {}
        binary_data = configmap.get("binaryData", {}) or {}
        return sorted({*(str(k) for k in data), *(str(k) for k in binary_data)})

    def _parse_dependency_event(
        self,
        pod: dict,
        event: dict[str, Any],
        context: dict,
    ) -> dict[str, Any] | None:
        message = str(event.get("message", ""))
        configmap_refs = self._collect_configmap_refs(pod)
        secret_refs = self._collect_secret_refs(pod)

        match = self.CONFIGMAP_NOT_FOUND_RE.search(message)
        if match:
            name = str(match.group("name"))
            surfaces = [ref["surface"] for ref in configmap_refs if ref["name"] == name]
            if surfaces:
                return {
                    "kind": "ConfigMap",
                    "name": name,
                    "surfaces": surfaces,
                    "reason": str(event.get("reason", "")),
                    "timestamp": self._event_time(event),
                }

        match = self.SECRET_NOT_FOUND_RE.search(message)
        if match:
            name = str(match.group("name"))
            surfaces = [ref["surface"] for ref in secret_refs if ref["name"] == name]
            if surfaces:
                return {
                    "kind": "Secret",
                    "name": name,
                    "surfaces": surfaces,
                    "reason": str(event.get("reason", "")),
                    "timestamp": self._event_time(event),
                }

        match = self.KEY_IN_CONFIGMAP_RE.search(message)
        if match:
            key = str(match.group(1))
            name = str(match.group(2))
            surfaces = [
                ref["surface"]
                for ref in configmap_refs
                if ref["name"] == name and ref.get("key") == key
            ]
            if surfaces and key not in self._configmap_available_keys(context, name):
                return {
                    "kind": "ConfigMapKey",
                    "name": name,
                    "key": key,
                    "surfaces": surfaces,
                    "reason": str(event.get("reason", "")),
                    "timestamp": self._event_time(event),
                }

        match = self.NONEXISTENT_KEY_RE.search(message)
        if match:
            key = str(match.group(1))
            volume_match = self.VOLUME_NAME_RE.search(message)
            volume_name = str(volume_match.group(1)) if volume_match else None
            candidates = [
                ref
                for ref in configmap_refs
                if ref.get("key") == key
                and (volume_name is None or ref.get("volume") == volume_name)
            ]
            if len(candidates) == 1:
                name = candidates[0]["name"]
                if key not in self._configmap_available_keys(context, name):
                    return {
                        "kind": "ConfigMapKey",
                        "name": name,
                        "key": key,
                        "surfaces": [candidates[0]["surface"]],
                        "reason": str(event.get("reason", "")),
                        "timestamp": self._event_time(event),
                    }

        return None

    def _waiting_config_error(self, pod: dict) -> tuple[bool, str]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") == "CreateContainerConfigError":
                return True, str(status.get("name", "<container>"))
        return False, "<container>"

    def _all_regular_containers_ready(self, pod: dict) -> bool:
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        if not spec_containers or len(statuses) < len(spec_containers):
            return False
        return all(
            bool(status.get("ready")) for status in statuses[: len(spec_containers)]
        )

    def _analyze(
        self,
        pod: dict,
        events: list[dict],
        context: dict,
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        recent_events = self._ordered_recent_events(timeline)
        dependency_events: list[dict[str, Any]] = []
        for event in recent_events:
            parsed = self._parse_dependency_event(pod, event, context)
            if parsed is not None:
                dependency_events.append(parsed)

        if not dependency_events:
            return None

        primary = dependency_events[-1]
        timestamps = [
            item["timestamp"]
            for item in dependency_events
            if isinstance(item.get("timestamp"), datetime)
        ]
        span_seconds = 0.0
        if len(timestamps) >= 2:
            span_seconds = (max(timestamps) - min(timestamps)).total_seconds()
            if span_seconds > self.MAX_CHAIN_SPAN_SECONDS:
                return None

        blocking_reasons = [
            str(event.get("reason", ""))
            for event in recent_events
            if event.get("reason") in self.STARTUP_BLOCK_REASONS
        ]
        blocking_reasons = list(
            dict.fromkeys(reason for reason in blocking_reasons if reason)
        )
        if not blocking_reasons:
            return None

        waiting_config_error, container_name = self._waiting_config_error(pod)
        if not waiting_config_error and len(blocking_reasons) < 2:
            return None

        latest_failure = primary.get("timestamp")
        success_after_failure = False
        if isinstance(latest_failure, datetime):
            for event in recent_events:
                reason = str(event.get("reason", ""))
                event_ts = self._event_time(event)
                if reason not in self.START_SUCCESS_REASONS or not isinstance(
                    event_ts, datetime
                ):
                    continue
                if event_ts > latest_failure:
                    success_after_failure = True
                    break

        if success_after_failure and self._all_regular_containers_ready(pod):
            return None

        return {
            "dependency": primary,
            "blocking_reasons": blocking_reasons,
            "waiting_config_error": waiting_config_error,
            "container_name": container_name,
            "event_count": len(dependency_events),
            "span_seconds": span_seconds,
            "success_after_failure": success_after_failure,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._analyze(pod, events, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._analyze(pod, events, context)
        if candidate is None:
            raise ValueError(
                "ConfigDependencyMissingChain explain() called without match"
            )

        dependency = candidate["dependency"]
        dep_kind = dependency["kind"]
        dep_name = dependency["name"]
        key = dependency.get("key")
        container_name = candidate["container_name"]

        if dep_kind == "ConfigMapKey":
            dependency_desc = f"required key '{key}' from ConfigMap '{dep_name}'"
            root_message = f"Missing ConfigMap key '{key}' blocked startup"
            dependency_code = "CONFIGMAP_KEY_MISSING"
        elif dep_kind == "Secret":
            dependency_desc = f"Secret '{dep_name}'"
            root_message = f"Missing Secret '{dep_name}' blocked startup"
            dependency_code = "SECRET_DEPENDENCY_MISSING"
        else:
            dependency_desc = f"ConfigMap '{dep_name}'"
            root_message = f"Missing ConfigMap '{dep_name}' blocked startup"
            dependency_code = "CONFIGMAP_DEPENDENCY_MISSING"

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIG_DEPENDENCY_REFERENCED",
                    message=f"Pod depends on {dependency_desc}",
                    role="configuration_context",
                ),
                Cause(
                    code=dependency_code,
                    message=f"Required configuration dependency is unavailable: {dependency_desc}",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="STARTUP_CONFIGURATION_CHAIN_BROKEN",
                    message="Kubelet cannot complete startup because required configuration cannot be resolved",
                    role="execution_intermediate",
                ),
                Cause(
                    code="POD_STARTUP_BLOCKED",
                    message="Pod remains blocked before normal container startup can complete",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Configuration dependency failure identified: {dependency_desc}",
            "Startup-blocking events observed: "
            + ", ".join(candidate["blocking_reasons"]),
        ]
        if candidate["waiting_config_error"]:
            evidence.append(
                f"Container '{container_name}' is waiting with CreateContainerConfigError"
            )
        if candidate["event_count"] > 1:
            minutes = candidate["span_seconds"] / 60.0
            evidence.append(
                f"Dependency failure persisted across {candidate['event_count']} related events over {minutes:.1f} minutes"
            )
        if not candidate["success_after_failure"]:
            evidence.append(
                "No successful container start was observed after the dependency failure"
            )

        object_key = (
            f"configmap:{dep_name}" if dep_kind != "Secret" else f"secret:{dep_name}"
        )
        object_evidence = {
            object_key: [
                *dependency["surfaces"],
                "Missing dependency is directly blocking Pod startup",
            ],
            f"pod:{pod.get('metadata', {}).get('name', '<pod>')}": [
                "Pod remains blocked by a missing configuration dependency"
            ],
        }
        if dep_kind == "ConfigMapKey" and key:
            object_evidence[object_key].insert(0, f"Required key '{key}' is absent")

        return {
            "root_cause": root_message,
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The workload references a ConfigMap or Secret that was never created in the Pod namespace",
                "A configuration object was deleted or renamed while the Pod spec still points to the old dependency",
                "The manifest expects a configuration key that is absent from the current ConfigMap data",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod.get('metadata', {}).get('name', '<pod>')}",
                "kubectl get configmap,secret",
                "Verify env, envFrom, and volume references in the Pod spec",
            ],
        }
