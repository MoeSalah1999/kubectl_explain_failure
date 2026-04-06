from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DeploymentRolloutOscillationRule(FailureRule):
    """
    Detects a Deployment rollout that repeatedly advances the newest ReplicaSet,
    restores an older one, and then retries the newest revision again.
    """

    name = "DeploymentRolloutOscillation"
    category = "Temporal"
    priority = 74
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["deployment", "replicaset"],
        "context": ["timeline"],
    }
    blocks = [
        "DeploymentReplicaMismatch",
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetUnavailable",
        "DeploymentRolloutStalled",
    ]

    WINDOW_MINUTES = 45
    MIN_DURATION_SECONDS = 180
    MIN_SCALE_EVENTS = 5
    SCALE_RE = re.compile(
        r"scaled\s+(up|down)\s+replica\s+set\s+([^\s]+)\s+to\s+(\d+)",
        re.IGNORECASE,
    )
    CONTROLLER_COMPONENTS = {"deployment-controller", "deploymentcontroller"}
    CACHE_KEY = "_deployment_rollout_oscillation_candidate"

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_timestamp(self, event: dict[str, Any]) -> datetime | None:
        raw = (
            event.get("lastTimestamp")
            or event.get("eventTime")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _pod_owned_replicaset(self, pod: dict[str, Any]) -> str | None:
        for ref in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == "replicaset" and (
                ref.get("controller") is True or "controller" not in ref
            ):
                return str(ref.get("name", ""))
        return None

    def _deployment_name_for_object(self, obj: dict[str, Any]) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == "deployment" and ref.get("name"):
                return str(ref["name"])
        return None

    def _candidate_deployment(
        self,
        pod: dict[str, Any],
        deployments: dict[str, dict[str, Any]],
        replicasets: dict[str, dict[str, Any]],
    ) -> tuple[str, dict[str, Any]] | None:
        namespace = self._namespace(pod)

        pod_rs_name = self._pod_owned_replicaset(pod)
        if pod_rs_name:
            rs = replicasets.get(pod_rs_name)
            if rs:
                dep_name = self._deployment_name_for_object(rs)
                if dep_name:
                    dep = deployments.get(dep_name)
                    if dep and self._namespace(dep) == namespace:
                        return dep_name, dep

        in_namespace = [
            (name, dep)
            for name, dep in deployments.items()
            if self._namespace(dep) == namespace
        ]
        if len(in_namespace) == 1:
            return in_namespace[0]

        return next(iter(deployments.items()), None)

    def _owned_replicasets(
        self,
        deployment_name: str,
        deployment_namespace: str,
        replicasets: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        owned: dict[str, dict[str, Any]] = {}
        for rs_name, rs in replicasets.items():
            if self._namespace(rs) != deployment_namespace:
                continue
            owner_name = self._deployment_name_for_object(rs)
            if owner_name == deployment_name or rs_name.startswith(
                f"{deployment_name}-"
            ):
                owned[rs_name] = rs
        return owned

    def _revision(self, obj: dict[str, Any]) -> int:
        annotations = obj.get("metadata", {}).get("annotations", {}) or {}
        return self._as_int(annotations.get("deployment.kubernetes.io/revision"), -1)

    def _current_replicas(self, rs: dict[str, Any]) -> int:
        status = rs.get("status", {}) or {}
        spec = rs.get("spec", {}) or {}
        return max(
            self._as_int(status.get("replicas"), 0),
            self._as_int(spec.get("replicas"), 0),
        )

    def _available_replicas(self, rs: dict[str, Any]) -> int:
        status = rs.get("status", {}) or {}
        return self._as_int(
            status.get("availableReplicas", status.get("readyReplicas", 0)),
            0,
        )

    def _selector_string(self, deployment: dict[str, Any]) -> str:
        match_labels = (
            deployment.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
        )
        if not match_labels:
            return "<deployment-selector>"
        return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))

    def _rollout_actions(
        self,
        timeline: Timeline,
        deployment_name: str,
        replicaset_names: set[str],
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if self._event_reason(event) != "scalingreplicaset":
                continue
            source = self._source_component(event)
            if source and source not in self.CONTROLLER_COMPONENTS:
                continue

            match = self.SCALE_RE.search(str(event.get("message", "")))
            if not match:
                continue

            rs_name = match.group(2)
            if rs_name not in replicaset_names:
                continue

            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", ""))
            message_lower = str(event.get("message", "")).lower()
            if involved_name and involved_name not in {deployment_name, rs_name}:
                if (
                    deployment_name.lower() not in message_lower
                    and rs_name.lower() not in message_lower
                ):
                    continue

            actions.append(
                {
                    "rs_name": rs_name,
                    "direction": match.group(1).lower(),
                    "timestamp": self._event_timestamp(event),
                }
            )

        actions.sort(
            key=lambda item: item.get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return actions

    def _pattern_details(
        self,
        actions: list[dict[str, Any]],
        new_rs_name: str,
        old_rs_names: set[str],
    ) -> dict[str, Any] | None:
        labels: list[str] = []
        display: list[str] = []
        counts = {"new-up": 0, "new-down": 0, "old-up": 0, "old-down": 0}
        per_rs: dict[str, dict[str, int]] = {}

        for action in actions:
            rs_name = action["rs_name"]
            label_prefix = "new" if rs_name == new_rs_name else "old"
            if label_prefix == "old" and rs_name not in old_rs_names:
                continue
            label = f"{label_prefix}-{action['direction']}"
            counts[label] += 1
            per_rs.setdefault(rs_name, {"up": 0, "down": 0})
            per_rs[rs_name][action["direction"]] += 1
            if not labels or labels[-1] != label:
                labels.append(label)
                display.append(f"{rs_name} {action['direction']}")

        if (
            counts["new-up"] < 2
            or counts["new-down"] < 1
            or counts["old-up"] < 1
            or counts["old-down"] < 1
            or len(labels) < 5
        ):
            return None

        try:
            start = labels.index("new-up")
            old_down = labels.index("old-down", start + 1)
            new_down = labels.index("new-down", old_down + 1)
            old_up = labels.index("old-up", old_down + 1)
            labels.index("new-up", max(new_down, old_up) + 1)
        except ValueError:
            return None

        return {"display": display, "counts": counts, "per_rs": per_rs}

    def _analyze_rollout(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        objects = context.get("objects", {}) or {}
        deployments = objects.get("deployment", {}) or {}
        replicasets = objects.get("replicaset", {}) or {}
        if not deployments or not replicasets:
            return None

        deployment_entry = self._candidate_deployment(pod, deployments, replicasets)
        if deployment_entry is None:
            return None

        deployment_name, deployment = deployment_entry
        rollout_rs = self._owned_replicasets(
            deployment_name,
            self._namespace(deployment),
            replicasets,
        )
        if len(rollout_rs) < 2:
            return None

        status = deployment.get("status", {}) or {}
        spec = deployment.get("spec", {}) or {}
        metadata = deployment.get("metadata", {}) or {}

        desired = self._as_int(spec.get("replicas", status.get("replicas", 1)), 1)
        updated = self._as_int(status.get("updatedReplicas"), 0)
        available = self._as_int(status.get("availableReplicas"), 0)
        ready = self._as_int(status.get("readyReplicas"), 0)
        generation = self._as_int(metadata.get("generation"), 0)
        observed_generation = self._as_int(status.get("observedGeneration"), generation)
        if desired <= 0 or (
            generation and observed_generation and observed_generation < generation
        ):
            return None

        sorted_rs = sorted(
            rollout_rs.items(),
            key=lambda item: (self._revision(item[1]), item[0]),
        )
        new_rs_name, new_rs = sorted_rs[-1]
        older_rs = [(name, rs) for name, rs in sorted_rs[:-1]]
        old_rs_names = {name for name, _ in older_rs}

        actions = self._rollout_actions(timeline, deployment_name, set(rollout_rs))
        if len(actions) < self.MIN_SCALE_EVENTS:
            return None

        timestamps = [
            a["timestamp"] for a in actions if isinstance(a.get("timestamp"), datetime)
        ]
        if len(timestamps) < 2:
            return None
        duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        if duration_seconds < self.MIN_DURATION_SECONDS:
            return None

        pattern = self._pattern_details(actions, new_rs_name, old_rs_names)
        if pattern is None:
            return None

        new_rs_replicas = self._current_replicas(new_rs)
        new_rs_available = self._available_replicas(new_rs)
        old_replicas = sum(self._current_replicas(rs) for _, rs in older_rs)
        rollout_incomplete = (
            updated < desired
            or available < desired
            or ready < desired
            or old_replicas > 0
            or new_rs_available < new_rs_replicas
        )
        if not rollout_incomplete:
            return None

        return {
            "deployment_name": deployment_name,
            "deployment": deployment,
            "desired": desired,
            "updated": updated,
            "available": available,
            "generation": generation,
            "observed_generation": observed_generation,
            "new_rs_name": new_rs_name,
            "new_rs_revision": self._revision(new_rs),
            "new_rs_replicas": new_rs_replicas,
            "new_rs_available": new_rs_available,
            "older_rs": older_rs,
            "duration_seconds": duration_seconds,
            "pattern": pattern,
            "selector": self._selector_string(deployment),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._analyze_rollout(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._analyze_rollout(pod, context)
        if candidate is None:
            raise ValueError(
                "DeploymentRolloutOscillation explain() called without match"
            )

        deployment_name = candidate["deployment_name"]
        desired = candidate["desired"]
        available = candidate["available"]
        updated = candidate["updated"]
        observed_generation = candidate["observed_generation"]
        generation = candidate["generation"]
        pattern = candidate["pattern"]
        counts = pattern["counts"]
        minutes = candidate["duration_seconds"] / 60.0

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_GENERATION_OBSERVED",
                    message=f"Deployment '{deployment_name}' has been observed at generation {observed_generation}",
                    role="controller_context",
                ),
                Cause(
                    code="DEPLOYMENT_ROLLOUT_OSCILLATION",
                    message="The rollout keeps reversing between the newest and older ReplicaSets instead of converging",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="ROLLING_UPDATE_DIRECTION_REVERSED",
                    message="ReplicaSet scaling direction flipped from promotion to rollback and then back to retry",
                    role="control_loop",
                ),
                Cause(
                    code="DEPLOYMENT_FAILED_TO_CONVERGE",
                    message=f"Deployment remains below target availability ({available}/{desired}) while revisions continue to alternate",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"deployment:{deployment_name}": [
                f"observedGeneration={observed_generation}, generation={generation or observed_generation}",
                f"updatedReplicas={updated}, availableReplicas={available}, desiredReplicas={desired}",
                "ReplicaSet scaling direction reversed and then retried within one rollout window",
            ],
            f"replicaset:{candidate['new_rs_name']}": [
                f"revision={candidate['new_rs_revision']}",
                f"scaleUpEvents={counts['new-up']}, scaleDownEvents={counts['new-down']}",
                f"availableReplicas={candidate['new_rs_available']}/{candidate['new_rs_replicas']}",
            ],
        }
        for old_rs_name, old_rs in candidate["older_rs"]:
            rs_counts = pattern["per_rs"].get(old_rs_name, {"up": 0, "down": 0})
            object_evidence[f"replicaset:{old_rs_name}"] = [
                f"revision={self._revision(old_rs)}",
                f"scaleUpEvents={rs_counts['up']}, scaleDownEvents={rs_counts['down']}",
                f"currentReplicas={self._current_replicas(old_rs)}, availableReplicas={self._available_replicas(old_rs)}",
            ]

        return {
            "root_cause": "Deployment rollout is oscillating between newer and older ReplicaSets",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Deployment '{deployment_name}' observed generation {observed_generation}/{generation or observed_generation} while rollout remains split across revisions",
                f"Scaling sequence alternated as: {' -> '.join(pattern['display'])}",
                f"Newest ReplicaSet '{candidate['new_rs_name']}' (revision {candidate['new_rs_revision']}) was scaled up {counts['new-up']} times and back down {counts['new-down']} time(s) over {minutes:.1f} minutes",
                f"Older ReplicaSets were first reduced and then restored during the same rollout window ({counts['old-down']} downscale, {counts['old-up']} upscale events)",
                f"Deployment still reports only {available}/{desired} available replicas and {updated}/{desired} updated replicas",
            ],
            "object_evidence": object_evidence,
            "likely_causes": [
                "Release automation or GitOps reconciliation is alternating between retrying and reverting the Deployment revision",
                "The new revision becomes unhealthy after partial rollout, causing an older ReplicaSet to be restored before another retry",
                "Multiple actors are updating the Deployment faster than the rollout can stabilize",
                "Controller-side failures in readiness, scheduling, or admission are causing repeated abandon-and-retry behavior for the new ReplicaSet",
            ],
            "suggested_checks": [
                f"kubectl rollout history deployment {deployment_name}",
                f"kubectl describe deployment {deployment_name}",
                f"kubectl get rs -l {candidate['selector']} -o wide",
                "kubectl get events --sort-by=.lastTimestamp",
            ],
        }
