from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DeploymentRolloutStalledRule(FailureRule):
    """
    Detects a Deployment rollout that has clearly stalled after the controller
    has observed the latest generation and started transitioning ReplicaSets.

    Real-world behavior:
    - a healthy Deployment rollout is not considered stalled just because
      `availableReplicas < spec.replicas`; fresh rollouts often spend some time
      in that state while the controller is still making progress
    - Kubernetes reports stalled rollout state through a combination of
      Deployment status, owned ReplicaSet progression, and repeated controller
      timeline activity over the deployment's progress deadline
    - the most common shape is: a new ReplicaSet is partially scaled, older
      replicas are still serving traffic, and the Deployment has not converged
      within its rollout window
    """

    name = "DeploymentRolloutStalled"
    category = "Compound"
    priority = 39
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
    ]

    DEFAULT_PROGRESS_DEADLINE_SECONDS = 600
    MIN_ROLLOUT_EVENTS = 2
    INCIDENT_WINDOW_MINUTES = 45
    CONTROLLER_COMPONENTS = {
        "deployment-controller",
        "deploymentcontroller",
        "replicaset-controller",
    }
    ROLLOUT_REASONS = {
        "scalingreplicaset",
        "successfulcreate",
        "failedcreate",
    }
    SCALE_RE = re.compile(
        r"scaled\s+(up|down)\s+replica\s+set\s+([^\s]+)\s+to\s+(\d+)",
        re.IGNORECASE,
    )
    CACHE_KEY = "_deployment_rollout_stalled_candidate"

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _truthy(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() == "true"

    def _falsy(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

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

    def _span_seconds(self, events: list[dict[str, Any]]) -> float:
        timestamps = [self._event_timestamp(event) for event in events]
        usable = [ts for ts in timestamps if ts is not None]
        if len(usable) < 2:
            return 0.0
        return (max(usable) - min(usable)).total_seconds()

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

        for ref in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == "deployment":
                dep_name = str(ref.get("name", ""))
                dep = deployments.get(dep_name)
                if dep and self._namespace(dep) == namespace:
                    return dep_name, dep

        pod_rs_name = self._pod_owned_replicaset(pod)
        if pod_rs_name:
            rs = replicasets.get(pod_rs_name)
            if rs:
                dep_name_from_rs = self._deployment_name_for_object(rs)
                if dep_name_from_rs:
                    dep = deployments.get(dep_name_from_rs)
                    if dep and self._namespace(dep) == namespace:
                        return dep_name_from_rs, dep

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
            if owner_name == deployment_name:
                owned[rs_name] = rs
                continue

            if rs_name.startswith(f"{deployment_name}-"):
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

    def _ready_replicas(self, rs: dict[str, Any]) -> int:
        return self._as_int(rs.get("status", {}).get("readyReplicas"), 0)

    def _deployment_condition(
        self,
        deployment: dict[str, Any],
        condition_type: str,
    ) -> dict[str, Any] | None:
        for condition in deployment.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == condition_type:
                return condition
        return None

    def _selector_string(self, deployment: dict[str, Any]) -> str:
        match_labels = (
            deployment.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
        )
        if not match_labels:
            return "<deployment-selector>"
        return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))

    def _parse_scale_action(
        self,
        event: dict[str, Any],
        replicaset_names: set[str],
    ) -> tuple[str, str] | None:
        if self._event_reason(event) != "scalingreplicaset":
            return None

        source = self._source_component(event)
        if source and source not in self.CONTROLLER_COMPONENTS:
            return None

        match = self.SCALE_RE.search(str(event.get("message", "")))
        if not match:
            return None

        rs_name = match.group(2)
        if rs_name not in replicaset_names:
            return None

        return rs_name, match.group(1).lower()

    def _has_rollout_oscillation(
        self,
        events: list[dict[str, Any]],
        *,
        new_rs_name: str,
        older_rs_names: set[str],
    ) -> bool:
        if not older_rs_names:
            return False

        labels: list[str] = []
        counts = {"new-up": 0, "new-down": 0, "old-up": 0, "old-down": 0}

        for event in events:
            parsed = self._parse_scale_action(event, {new_rs_name, *older_rs_names})
            if parsed is None:
                continue

            rs_name, direction = parsed
            label = f"new-{direction}" if rs_name == new_rs_name else f"old-{direction}"
            counts[label] += 1
            if not labels or labels[-1] != label:
                labels.append(label)

        if (
            counts["new-up"] < 2
            or counts["new-down"] < 1
            or counts["old-up"] < 1
            or counts["old-down"] < 1
            or len(labels) < 5
        ):
            return False

        try:
            first_new_up = labels.index("new-up")
            first_old_down = labels.index("old-down", first_new_up + 1)
            rollback_new_down = labels.index("new-down", first_old_down + 1)
            rollback_old_up = labels.index("old-up", first_old_down + 1)
            labels.index("new-up", max(rollback_new_down, rollback_old_up) + 1)
        except ValueError:
            return False

        return True

    def _event_mentions_rollout(
        self,
        event: dict[str, Any],
        deployment_name: str,
        replicaset_names: set[str],
    ) -> bool:
        reason = self._event_reason(event)
        source = self._source_component(event)

        if (
            reason not in self.ROLLOUT_REASONS
            and source not in self.CONTROLLER_COMPONENTS
        ):
            return False

        involved = event.get("involvedObject", {}) or {}
        involved_name = str(involved.get("name", "")).lower()
        message = self._event_message(event)
        rollout_names = {
            deployment_name.lower(),
            *(name.lower() for name in replicaset_names),
        }

        if involved_name in rollout_names:
            return True

        return any(name in message for name in rollout_names)

    def _analyze_rollout(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
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
        deployment_namespace = self._namespace(deployment)
        rollout_rs = self._owned_replicasets(
            deployment_name,
            deployment_namespace,
            replicasets,
        )
        if not rollout_rs:
            return None

        status = deployment.get("status", {}) or {}
        spec = deployment.get("spec", {}) or {}
        metadata = deployment.get("metadata", {}) or {}

        desired = self._as_int(spec.get("replicas", status.get("replicas", 1)), 1)
        updated = self._as_int(status.get("updatedReplicas"), 0)
        available = self._as_int(status.get("availableReplicas"), 0)
        ready = self._as_int(status.get("readyReplicas"), 0)
        unavailable = self._as_int(
            status.get("unavailableReplicas"),
            max(0, desired - available),
        )
        generation = self._as_int(metadata.get("generation"), 0)
        observed_generation = self._as_int(status.get("observedGeneration"), generation)

        if desired <= 0:
            return None
        if generation and observed_generation and observed_generation < generation:
            return None

        rollout_incomplete = (
            updated < desired
            or available < desired
            or ready < desired
            or unavailable > 0
        )

        sorted_rs = sorted(
            rollout_rs.items(),
            key=lambda item: (self._revision(item[1]), item[0]),
        )
        new_rs_name, new_rs = sorted_rs[-1]
        older_rs = [
            (name, rs) for name, rs in sorted_rs[:-1] if self._current_replicas(rs) > 0
        ]

        new_rs_replicas = self._current_replicas(new_rs)
        new_rs_available = self._available_replicas(new_rs)
        new_rs_ready = self._ready_replicas(new_rs)
        old_available = sum(self._available_replicas(rs) for _, rs in older_rs)
        old_replicas = sum(self._current_replicas(rs) for _, rs in older_rs)

        progress_condition = self._deployment_condition(deployment, "Progressing")
        available_condition = self._deployment_condition(deployment, "Available")
        deadline_exceeded = bool(
            progress_condition
            and progress_condition.get("reason") == "ProgressDeadlineExceeded"
            and self._falsy(progress_condition.get("status"))
        )

        new_rs_stalled = bool(
            new_rs_replicas > 0
            and (new_rs_available < new_rs_replicas or new_rs_ready < new_rs_replicas)
        )
        old_rs_still_serving = old_replicas > 0 or old_available > 0

        if not rollout_incomplete:
            return None
        if not (new_rs_stalled or old_rs_still_serving):
            return None

        progress_deadline_seconds = self._as_int(
            spec.get("progressDeadlineSeconds"),
            self.DEFAULT_PROGRESS_DEADLINE_SECONDS,
        )
        incident_window_minutes = max(
            self.INCIDENT_WINDOW_MINUTES,
            (progress_deadline_seconds + 59) // 60 + 10,
        )
        recent_rollout_events = [
            event
            for event in timeline.events_within_window(incident_window_minutes)
            if self._event_mentions_rollout(
                event,
                deployment_name,
                set(rollout_rs),
            )
        ]
        recent_rollout_span_seconds = self._span_seconds(recent_rollout_events)

        if self._has_rollout_oscillation(
            recent_rollout_events,
            new_rs_name=new_rs_name,
            older_rs_names={name for name, _ in older_rs},
        ):
            return None

        if len(recent_rollout_events) < self.MIN_ROLLOUT_EVENTS:
            return None

        if (
            not deadline_exceeded
            and recent_rollout_span_seconds < progress_deadline_seconds
        ):
            return None

        latest_progress_message = ""
        if isinstance(progress_condition, dict):
            latest_progress_message = str(progress_condition.get("message", "")).strip()

        return {
            "deployment_name": deployment_name,
            "deployment": deployment,
            "desired": desired,
            "updated": updated,
            "available": available,
            "generation": generation,
            "observed_generation": observed_generation,
            "progress_deadline_seconds": progress_deadline_seconds,
            "rollout_span_seconds": recent_rollout_span_seconds,
            "recent_rollout_events": len(recent_rollout_events),
            "progress_condition": progress_condition,
            "available_condition": available_condition,
            "latest_progress_message": latest_progress_message,
            "new_rs_name": new_rs_name,
            "new_rs_revision": self._revision(new_rs),
            "new_rs_replicas": new_rs_replicas,
            "new_rs_available": new_rs_available,
            "older_rs": older_rs,
            "old_available": old_available,
            "old_replicas": old_replicas,
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
            raise ValueError("DeploymentRolloutStalled explain() called without match")

        deployment_name = candidate["deployment_name"]
        desired = candidate["desired"]
        available = candidate["available"]
        updated = candidate["updated"]
        observed_generation = candidate["observed_generation"]
        generation = candidate["generation"]
        new_rs_name = candidate["new_rs_name"]
        new_rs_revision = candidate["new_rs_revision"]
        new_rs_available = candidate["new_rs_available"]
        new_rs_replicas = candidate["new_rs_replicas"]
        old_available = candidate["old_available"]
        span_minutes = candidate["rollout_span_seconds"] / 60.0
        deadline_minutes = candidate["progress_deadline_seconds"] / 60.0
        progress_condition = candidate.get("progress_condition") or {}
        available_condition = candidate.get("available_condition") or {}

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_GENERATION_OBSERVED",
                    message=f"Deployment '{deployment_name}' has been observed at generation {observed_generation}",
                    role="controller_context",
                ),
                Cause(
                    code="DEPLOYMENT_ROLLOUT_PROGRESS_STALLED",
                    message="The Deployment controller is no longer making rollout progress toward the desired replica set state",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="NEW_REPLICASET_NOT_BECOMING_AVAILABLE",
                    message=f"New ReplicaSet '{new_rs_name}' is scaled but not becoming fully available",
                    role="controller_intermediate",
                ),
                Cause(
                    code="DEPLOYMENT_REMAINS_BELOW_TARGET_AVAILABILITY",
                    message=f"Deployment availability remains below target ({available}/{desired}) while the rollout is incomplete",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Deployment '{deployment_name}' observed generation {observed_generation}/{generation or observed_generation} but only {available}/{desired} replicas are available",
            f"New ReplicaSet '{new_rs_name}' (revision {new_rs_revision}) has {new_rs_available}/{new_rs_replicas} available replicas",
            f"Recent controller rollout activity spans {span_minutes:.1f} minutes across {candidate['recent_rollout_events']} events, exceeding the {deadline_minutes:.1f} minute progress deadline",
        ]
        if candidate["old_replicas"] > 0 or old_available > 0:
            evidence.append(
                f"Older ReplicaSets still hold {candidate['old_replicas']} replicas and {old_available} available replicas, so the rollout has not converged"
            )
        if progress_condition.get("reason") == "ProgressDeadlineExceeded":
            evidence.append(
                "Deployment Progressing condition reports ProgressDeadlineExceeded"
            )
        if self._falsy(available_condition.get("status")) and available_condition.get(
            "reason"
        ):
            evidence.append(
                f"Deployment Available condition is False ({available_condition.get('reason')})"
            )

        object_evidence = {
            f"deployment:{deployment_name}": [
                f"observedGeneration={observed_generation}, generation={generation or observed_generation}",
                f"updatedReplicas={updated}, availableReplicas={available}, desiredReplicas={desired}",
            ],
            f"replicaset:{new_rs_name}": [
                f"revision={new_rs_revision}",
                f"availableReplicas={new_rs_available}/{new_rs_replicas}",
            ],
        }

        if progress_condition.get("reason") == "ProgressDeadlineExceeded":
            object_evidence[f"deployment:{deployment_name}"].append(
                "Progressing=False (ProgressDeadlineExceeded)"
            )

        for old_rs_name, old_rs in candidate["older_rs"]:
            object_evidence[f"replicaset:{old_rs_name}"] = [
                f"Older rollout revision still active with {self._current_replicas(old_rs)} replicas",
                f"availableReplicas={self._available_replicas(old_rs)}",
            ]

        likely_causes = [
            "New revision pods are failing readiness, startup, or container runtime checks so the new ReplicaSet never becomes available",
            "Scheduling or cluster capacity constraints are slowing the replacement pods enough to exhaust the Deployment progress deadline",
            "Older pods cannot drain or terminate cleanly because of PodDisruptionBudget, long shutdown time, or stuck finalization",
            "ReplicaSet or admission-level errors are preventing the Deployment controller from completing the intended scale transition",
        ]

        suggested_checks = [
            f"kubectl rollout status deployment {deployment_name}",
            f"kubectl describe deployment {deployment_name}",
            f"kubectl describe replicaset {new_rs_name}",
            f"kubectl get rs,pods -l {candidate['selector']} -o wide",
        ]

        if candidate["latest_progress_message"]:
            object_evidence[f"deployment:{deployment_name}"].append(
                candidate["latest_progress_message"]
            )

        return {
            "root_cause": "Deployment rollout stalled while transitioning to a new ReplicaSet",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": suggested_checks,
        }
