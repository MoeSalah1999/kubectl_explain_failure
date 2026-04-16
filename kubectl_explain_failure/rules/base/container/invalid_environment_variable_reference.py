from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class InvalidEnvironmentVariableReferenceRule(FailureRule):
    """
    Detect envFrom sources whose keys cannot be materialized as environment
    variables.

    Real-world Kubernetes behavior:
    - this warning is emitted for envFrom ConfigMap / Secret sources whose keys
      are not valid environment variable names
    - kubelet skips those keys instead of failing Pod startup
    - the workload can still start, but expected configuration values will be
      missing from the container environment
    """

    name = "InvalidEnvironmentVariableReference"
    category = "Container"
    priority = 44
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["configmap", "secret"],
    }

    WINDOW_MINUTES = 15
    WARNING_REASONS = {"InvalidEnvironmentVariableNames", "InvalidVariableNames"}
    START_SUCCESS_REASONS = {"Pulled", "Created", "Started"}
    EVENT_RE = re.compile(
        r"Keys \[(?P<keys>[^\]]+)\] from the EnvFrom "
        r"(?P<kind>configMap|secret) (?P<name>[^\s]+) were skipped since they "
        r"are considered invalid environment variable names\.?",
        re.IGNORECASE,
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        if not recent:
            return list(timeline.raw_events)

        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _collect_envfrom_refs(self, pod: dict[str, Any]) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        spec = pod.get("spec", {}) or {}

        for container_group in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = str(container.get("name", "<container>"))
                for env_from in container.get("envFrom", []) or []:
                    prefix = env_from.get("prefix")
                    surface = f"Referenced by envFrom in container '{container_name}'"
                    if isinstance(prefix, str) and prefix:
                        surface += f" with prefix '{prefix}'"

                    configmap_ref = env_from.get("configMapRef") or {}
                    if configmap_ref.get("name"):
                        refs.append(
                            {
                                "kind": "configmap",
                                "name": str(configmap_ref["name"]),
                                "surface": surface,
                            }
                        )

                    secret_ref = env_from.get("secretRef") or {}
                    if secret_ref.get("name"):
                        refs.append(
                            {
                                "kind": "secret",
                                "name": str(secret_ref["name"]),
                                "surface": surface,
                            }
                        )

        return refs

    def _parse_keys(self, raw_keys: str) -> list[str]:
        return [
            key
            for key in (
                part.strip().strip('"').strip("'") for part in raw_keys.split(",")
            )
            if key
        ]

    def _parse_warning_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        if event.get("reason") not in self.WARNING_REASONS:
            return None

        message = str(event.get("message", ""))
        match = self.EVENT_RE.search(message)
        if not match:
            return None

        source_name = str(match.group("name")).strip().rstrip(".").strip('"').strip("'")
        if "/" in source_name:
            source_name = source_name.split("/", 1)[1]

        source_kind = "configmap"
        if match.group("kind").lower() == "secret":
            source_kind = "secret"

        keys = self._parse_keys(match.group("keys"))
        if not keys:
            return None

        return {
            "kind": source_kind,
            "name": source_name,
            "keys": keys,
            "timestamp": self._event_time(event),
            "occurrences": self._occurrences(event),
            "message": message,
        }

    def _source_keys(self, context: dict[str, Any], kind: str, name: str) -> list[str]:
        source = (context.get("objects", {}).get(kind, {}) or {}).get(name)
        if not isinstance(source, dict):
            return []

        data = source.get("data", {}) or {}
        binary_data = source.get("binaryData", {}) or {}
        string_data = source.get("stringData", {}) or {}
        return sorted(
            {
                *(str(key) for key in data),
                *(str(key) for key in binary_data),
                *(str(key) for key in string_data),
            }
        )

    def _containers_running(self, pod: dict[str, Any]) -> bool:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            state = (status.get("state", {}) or {}).get("running")
            if isinstance(state, dict):
                return True
        return False

    def _has_start_success_after(
        self,
        events: list[dict[str, Any]],
        latest_warning: datetime | None,
    ) -> bool:
        if latest_warning is None:
            return False

        for event in events:
            if event.get("reason") not in self.START_SUCCESS_REASONS:
                continue
            ts = self._event_time(event)
            if isinstance(ts, datetime) and ts > latest_warning:
                return True
        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        refs = self._collect_envfrom_refs(pod)
        if not refs:
            return None

        ordered_events = self._ordered_recent_events(timeline)
        candidates: dict[tuple[str, str], dict[str, Any]] = {}

        for event in ordered_events:
            parsed = self._parse_warning_event(event)
            if parsed is None:
                continue

            matching_refs = [
                ref
                for ref in refs
                if ref["kind"] == parsed["kind"] and ref["name"] == parsed["name"]
            ]
            if not matching_refs:
                continue

            key = (parsed["kind"], parsed["name"])
            candidate = candidates.setdefault(
                key,
                {
                    "kind": parsed["kind"],
                    "name": parsed["name"],
                    "invalid_keys": set(),
                    "surfaces": [],
                    "event_occurrences": 0,
                    "warning_events": 0,
                    "latest_warning": None,
                    "latest_message": "",
                },
            )
            candidate["invalid_keys"].update(parsed["keys"])
            candidate["surfaces"].extend(ref["surface"] for ref in matching_refs)
            candidate["event_occurrences"] += parsed["occurrences"]
            candidate["warning_events"] += 1

            latest_warning = candidate["latest_warning"]
            parsed_ts = parsed["timestamp"]
            if latest_warning is None or (
                isinstance(parsed_ts, datetime) and parsed_ts >= latest_warning
            ):
                candidate["latest_warning"] = parsed_ts
                candidate["latest_message"] = parsed["message"]

        if not candidates:
            return None

        for candidate in candidates.values():
            candidate["invalid_keys"] = sorted(
                str(key) for key in candidate["invalid_keys"]
            )
            candidate["surfaces"] = list(dict.fromkeys(candidate["surfaces"]))
            candidate["current_keys"] = self._source_keys(
                context, candidate["kind"], candidate["name"]
            )
            candidate["current_invalid_keys"] = [
                key
                for key in candidate["invalid_keys"]
                if key in set(candidate["current_keys"])
            ]
            candidate["start_continued"] = self._has_start_success_after(
                ordered_events,
                candidate["latest_warning"],
            ) or (
                pod.get("status", {}).get("phase") == "Running"
                and self._containers_running(pod)
            )

        return max(
            candidates.values(),
            key=lambda candidate: (
                candidate["event_occurrences"],
                len(candidate["invalid_keys"]),
                len(candidate["surfaces"]),
                candidate["name"],
            ),
        )

    def matches(self, pod, events, context) -> bool:
        return self._best_candidate(pod, context) is not None

    def explain(self, pod, events, context):
        candidate = self._best_candidate(pod, context)
        if candidate is None:
            raise ValueError(
                "InvalidEnvironmentVariableReference explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        source_kind = candidate["kind"]
        source_name = candidate["name"]
        source_label = "ConfigMap" if source_kind == "configmap" else "Secret"
        invalid_keys = ", ".join(candidate["invalid_keys"])

        confidence = 0.88
        if candidate["current_keys"]:
            confidence += 0.02
        if candidate["event_occurrences"] > 1:
            confidence += 0.01
        if candidate["start_continued"]:
            confidence += 0.01

        chain = CausalChain(
            causes=[
                Cause(
                    code="ENVFROM_SOURCE_REFERENCED",
                    message=(
                        f"Pod imports environment variables from {source_label} '{source_name}' using envFrom"
                    ),
                    role="configuration_context",
                ),
                Cause(
                    code="INVALID_ENVIRONMENT_VARIABLE_KEYS",
                    message=(
                        f"{source_label} '{source_name}' contains key names that cannot become environment variables"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_SKIPS_INVALID_ENV_KEYS",
                    message=(
                        "Kubelet skips invalid envFrom keys instead of injecting them into the container environment"
                    ),
                    role="runtime_symptom",
                ),
                Cause(
                    code="APPLICATION_ENV_CONFIGURATION_INCOMPLETE",
                    message=(
                        "The workload may start without configuration values it expected from envFrom"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"{source_label} '{source_name}' exposed invalid envFrom key(s): {invalid_keys}",
            f"Observed {candidate['event_occurrences']} InvalidEnvironmentVariableNames warning occurrence(s) for the current Pod",
        ]
        if candidate["start_continued"]:
            evidence.append(
                "Container startup continued after the warning, which matches kubelet skipping invalid envFrom keys instead of blocking the Pod"
            )

        object_evidence = {
            f"{source_kind}:{source_name}": [
                f"Kubelet skipped invalid envFrom key(s): {invalid_keys}",
                *candidate["surfaces"],
            ],
            f"pod:{pod_name}": ["Warning event reason=InvalidEnvironmentVariableNames"],
        }
        if candidate["current_invalid_keys"]:
            object_evidence[f"{source_kind}:{source_name}"].append(
                "Current source still contains skipped key(s): "
                + ", ".join(candidate["current_invalid_keys"])
            )
        if candidate["current_keys"]:
            object_evidence[f"{source_kind}:{source_name}"].append(
                "Available keys: " + ", ".join(candidate["current_keys"])
            )

        return {
            "root_cause": (
                f"envFrom source '{source_name}' contains keys that are not valid environment variable names"
            ),
            "confidence": min(0.92, confidence),
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "ConfigMap or Secret keys contain dots, hyphens, or leading digits that are valid data keys but invalid environment variable names",
                "A file-oriented configuration object was reused with envFrom without renaming the keys for environment-variable consumption",
                "An envFrom prefix was omitted or was not enough to turn the imported keys into valid environment variable names",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get {source_kind} {source_name} -o yaml",
                "Rename the offending keys or replace envFrom with explicit env.valueFrom entries for the keys the container actually needs",
            ],
        }
