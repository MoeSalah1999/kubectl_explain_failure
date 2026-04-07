from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DeploymentRollbackLoopRule(FailureRule):
    """
    Detects a Deployment that restores an older stable ReplicaSet after a newer
    revision fails and then retries rollout with another newer revision.
    """

    name = "DeploymentRollbackLoop"
    category = "Compound"
    priority = 44
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["deployment", "replicaset"],
        "context": ["timeline"],
    }
    blocks = [
        "DeploymentRolloutStalled",
        "DeploymentReplicaMismatch",
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetUnavailable",
    ]

    WINDOW_MINUTES = 60
    MIN_SCALE_EVENTS = 5
    MIN_DURATION_SECONDS = 300
    CONTROLLER_COMPONENTS = {"deployment-controller", "deploymentcontroller"}
    SCALE_RE = re.compile(
        r"scaled\s+(up|down)\s+replica\s+set\s+([^\s]+)\s+to\s+(\d+)",
        re.IGNORECASE,
    )
    CACHE_KEY = "_deployment_rollback_loop_candidate"

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

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

    def _action_timestamp(self, action: dict[str, Any]) -> datetime | None:
        value = action.get("timestamp")
        if isinstance(value, datetime):
            return value
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

    def _deployment_condition(
        self,
        deployment: dict[str, Any],
        condition_type: str,
    ) -> dict[str, Any] | None:
        for condition in deployment.get("status", {}).get("conditions", []) or []:
            if condition.get("type") == condition_type:
                return condition
        return None

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
            involved_name = str(involved.get("name", "")).lower()
            message_lower = str(event.get("message", "")).lower()
            if involved_name and involved_name not in {
                deployment_name.lower(),
                rs_name.lower(),
            }:
                if (
                    deployment_name.lower() not in message_lower
                    and rs_name.lower() not in message_lower
                ):
                    continue

            actions.append(
                {
                    "rs_name": rs_name,
                    "direction": match.group(1).lower(),
                    "replicas": self._as_int(match.group(3), 0),
                    "timestamp": self._event_timestamp(event),
                }
            )

        actions.sort(
            key=lambda item: self._action_timestamp(item)
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return actions

    def _rollback_pattern(
        self,
        actions: list[dict[str, Any]],
        *,
        stable_rs_name: str,
        stable_revision: int,
        latest_rs_name: str,
        revisions: dict[str, int],
    ) -> dict[str, Any] | None:
        if len(actions) < self.MIN_SCALE_EVENTS:
            return None

        for i, first_new in enumerate(actions):
            first_revision = revisions.get(first_new["rs_name"], -1)
            if (
                first_new["direction"] != "up"
                or first_new["rs_name"] == stable_rs_name
                or first_revision <= stable_revision
                or first_new["rs_name"] == latest_rs_name
            ):
                continue

            for j in range(i + 1, len(actions)):
                stable_down = actions[j]
                if (
                    stable_down["rs_name"] != stable_rs_name
                    or stable_down["direction"] != "down"
                ):
                    continue

                for k in range(j + 1, len(actions)):
                    failed_new_down = actions[k]
                    if (
                        failed_new_down["rs_name"] != first_new["rs_name"]
                        or failed_new_down["direction"] != "down"
                    ):
                        continue

                    for l in range(k + 1, len(actions)):
                        stable_restore = actions[l]
                        if (
                            stable_restore["rs_name"] != stable_rs_name
                            or stable_restore["direction"] != "up"
                        ):
                            continue

                        for m in range(l + 1, len(actions)):
                            retry_new = actions[m]
                            retry_revision = revisions.get(retry_new["rs_name"], -1)
                            if retry_new["direction"] != "up":
                                continue
                            if retry_new["rs_name"] == stable_rs_name:
                                continue
                            if retry_revision <= first_revision:
                                continue

                            timestamps: list[datetime] = []
                            for action in (
                                first_new,
                                stable_down,
                                failed_new_down,
                                stable_restore,
                                retry_new,
                            ):
                                timestamp = self._action_timestamp(action)
                                if timestamp is not None:
                                    timestamps.append(timestamp)
                            if len(timestamps) < 2:
                                continue

                            duration_seconds = (
                                max(timestamps) - min(timestamps)
                            ).total_seconds()
                            if duration_seconds < self.MIN_DURATION_SECONDS:
                                continue

                            return {
                                "failed_rs_name": first_new["rs_name"],
                                "failed_rs_revision": first_revision,
                                "retry_rs_name": retry_new["rs_name"],
                                "retry_rs_revision": retry_revision,
                                "duration_seconds": duration_seconds,
                                "display": [
                                    f"{first_new['rs_name']} up",
                                    f"{stable_rs_name} down",
                                    f"{failed_new_down['rs_name']} down",
                                    f"{stable_rs_name} up",
                                    f"{retry_new['rs_name']} up",
                                ],
                            }

        return None

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
        if len(rollout_rs) < 3:
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
        latest_rs_name, latest_rs = sorted_rs[-1]
        revisions = {name: self._revision(rs) for name, rs in sorted_rs}
        older_rs = list(sorted_rs[:-1])

        stable_rs_name, stable_rs = max(
            older_rs,
            key=lambda item: (
                self._available_replicas(item[1]),
                self._current_replicas(item[1]),
                self._revision(item[1]),
                item[0],
            ),
        )
        stable_revision = revisions[stable_rs_name]
        stable_current = self._current_replicas(stable_rs)
        stable_available = self._available_replicas(stable_rs)
        if stable_current <= 0 and stable_available <= 0:
            return None

        latest_revision = revisions[latest_rs_name]
        latest_current = self._current_replicas(latest_rs)
        latest_available = self._available_replicas(latest_rs)
        if latest_revision <= stable_revision or latest_current <= 0:
            return None

        abandoned_candidates = [
            (name, rs)
            for name, rs in older_rs
            if stable_revision < revisions[name] < latest_revision
            and self._current_replicas(rs) == 0
        ]
        if not abandoned_candidates:
            return None

        actions = self._rollout_actions(timeline, deployment_name, set(rollout_rs))
        pattern = self._rollback_pattern(
            actions,
            stable_rs_name=stable_rs_name,
            stable_revision=stable_revision,
            latest_rs_name=latest_rs_name,
            revisions=revisions,
        )
        if pattern is None:
            return None

        progress_condition = self._deployment_condition(deployment, "Progressing")
        available_condition = self._deployment_condition(deployment, "Available")
        rollout_incomplete = (
            updated < desired
            or available < desired
            or ready < desired
            or stable_current > 0
            or latest_available < latest_current
        )
        if not rollout_incomplete:
            return None

        return {
            "deployment_name": deployment_name,
            "desired": desired,
            "updated": updated,
            "available": available,
            "generation": generation,
            "observed_generation": observed_generation,
            "stable_rs_name": stable_rs_name,
            "stable_rs_revision": stable_revision,
            "stable_current": stable_current,
            "stable_available": stable_available,
            "failed_rs_name": pattern["failed_rs_name"],
            "failed_rs_revision": pattern["failed_rs_revision"],
            "failed_rs": rollout_rs[pattern["failed_rs_name"]],
            "latest_rs_name": latest_rs_name,
            "latest_rs_revision": latest_revision,
            "latest_current": latest_current,
            "latest_available": latest_available,
            "pattern": pattern,
            "progress_condition": progress_condition,
            "available_condition": available_condition,
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
            raise ValueError("DeploymentRollbackLoop explain() called without match")

        deployment_name = candidate["deployment_name"]
        desired = candidate["desired"]
        available = candidate["available"]
        updated = candidate["updated"]
        observed_generation = candidate["observed_generation"]
        generation = candidate["generation"]
        stable_rs_name = candidate["stable_rs_name"]
        stable_rs_revision = candidate["stable_rs_revision"]
        stable_current = candidate["stable_current"]
        stable_available = candidate["stable_available"]
        failed_rs_name = candidate["failed_rs_name"]
        failed_rs_revision = candidate["failed_rs_revision"]
        latest_rs_name = candidate["latest_rs_name"]
        latest_rs_revision = candidate["latest_rs_revision"]
        latest_current = candidate["latest_current"]
        latest_available = candidate["latest_available"]
        minutes = candidate["pattern"]["duration_seconds"] / 60.0
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
                    code="DEPLOYMENT_ROLLBACK_LOOP",
                    message="The Deployment keeps restoring an older stable ReplicaSet after a newer revision fails, then retries rollout again",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="OLDER_REPLICASET_RESTORED",
                    message=f"Older ReplicaSet '{stable_rs_name}' was brought back to carry traffic after revision {failed_rs_revision} stalled",
                    role="controller_intermediate",
                ),
                Cause(
                    code="DEPLOYMENT_FAILED_TO_CONVERGE",
                    message=f"Deployment remains below desired convergence with {available}/{desired} available replicas and only {updated}/{desired} updated replicas",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Deployment '{deployment_name}' observed generation {observed_generation}/{generation or observed_generation} while revisions {stable_rs_revision}, {failed_rs_revision}, and {latest_rs_revision} all appeared in the same rollout incident",
            f"Rollback sequence progressed as: {' -> '.join(candidate['pattern']['display'])}",
            f"Stable ReplicaSet '{stable_rs_name}' (revision {stable_rs_revision}) was restored to {stable_current} replicas with {stable_available} available replicas",
            f"Abandoned ReplicaSet '{failed_rs_name}' (revision {failed_rs_revision}) was scaled back down before the next rollout attempt",
            f"Newest ReplicaSet '{latest_rs_name}' (revision {latest_rs_revision}) is only {latest_available}/{latest_current} available after the retry loop over {minutes:.1f} minutes",
            f"Deployment still reports {available}/{desired} available replicas and {updated}/{desired} updated replicas",
        ]
        if progress_condition.get("reason") == "ProgressDeadlineExceeded":
            evidence.append(
                "Deployment Progressing condition reports ProgressDeadlineExceeded during the rollback loop"
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
                "Controller rollout history shows rollback to an older ReplicaSet before a new retry",
            ],
            f"replicaset:{stable_rs_name}": [
                f"revision={stable_rs_revision}",
                f"currentReplicas={stable_current}, availableReplicas={stable_available}",
            ],
            f"replicaset:{failed_rs_name}": [
                f"revision={failed_rs_revision}",
                f"currentReplicas={self._current_replicas(candidate['failed_rs'])}, availableReplicas={self._available_replicas(candidate['failed_rs'])}",
                "Earlier rollout attempt was abandoned during rollback",
            ],
            f"replicaset:{latest_rs_name}": [
                f"revision={latest_rs_revision}",
                f"currentReplicas={latest_current}, availableReplicas={latest_available}",
            ],
        }

        if progress_condition.get("reason") == "ProgressDeadlineExceeded":
            object_evidence[f"deployment:{deployment_name}"].append(
                "Progressing=False (ProgressDeadlineExceeded)"
            )
        if progress_condition.get("message"):
            object_evidence[f"deployment:{deployment_name}"].append(
                str(progress_condition.get("message"))
            )

        return {
            "root_cause": "Deployment rollout is stuck in a rollback loop between older and newer ReplicaSets",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Release automation or GitOps keeps reapplying a broken Deployment revision shortly after rolling back to the last stable one",
                "A new image or pod template repeatedly fails health checks, causing operators to restore the previous ReplicaSet before trying another patch",
                "Multiple delivery systems are alternately pushing rollback and rollout changes faster than the Deployment can stabilize",
                "The controller is retrying successive ReplicaSet revisions while an unresolved application or readiness regression remains in the new template",
            ],
            "suggested_checks": [
                f"kubectl rollout history deployment {deployment_name}",
                f"kubectl describe deployment {deployment_name}",
                f"kubectl get rs -l {candidate['selector']} -o wide",
                "Compare the last known good ReplicaSet template with the newer failed revisions before retrying rollout again",
            ],
        }
