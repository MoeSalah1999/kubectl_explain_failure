from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ReplicaOscillationRule(FailureRule):
    """
    Detects repeated scale-up / scale-down reversals for the same ReplicaSet
    within one incident window.

    Real-world behavior:
    - unlike a normal rollout handoff between old and new ReplicaSets, this
      pattern repeatedly changes the desired size of the same ReplicaSet
    - this often happens when HPA decisions, manual/GitOps desired replica
      changes, or conflicting controller inputs keep reversing each other
    - a single scale-up followed by one rollback is not enough; the signal is
      meaningful when the direction keeps flipping and the workload still has
      not converged
    """

    name = "ReplicaOscillation"
    category = "Temporal"
    priority = 69
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["replicaset"],
        "context": ["timeline"],
        "optional_objects": ["deployment", "hpa"],
    }
    blocks = [
        "DeploymentReplicaMismatch",
        "ReplicaSetUnavailable",
        "ReplicaSetCreateFailure",
    ]

    WINDOW_MINUTES = 30
    MIN_SCALE_EVENTS = 4
    MIN_DIRECTION_CHANGES = 3
    MIN_DURATION_SECONDS = 300
    SCALE_RE = re.compile(
        r"scaled\s+(up|down)\s+replica\s+set\s+([^\s]+)\s+to\s+(\d+)",
        re.IGNORECASE,
    )
    HPA_SIZE_RE = re.compile(r"new size:\s*(\d+)", re.IGNORECASE)
    CONTROLLER_COMPONENTS = {
        "deployment-controller",
        "deploymentcontroller",
        "replicaset-controller",
        "statefulset-controller",
    }
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    CACHE_KEY = "_replica_oscillation_candidate"

    def __init__(self) -> None:
        from kubectl_explain_failure.rules.temporal.base.controllers.deployment_rollout_oscillation import (
            DeploymentRolloutOscillationRule,
        )

        self._deployment_rollout_oscillation_rule = DeploymentRolloutOscillationRule()

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

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        items = list(enumerate(events))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_timestamp(item[1]) is None else 0,
                    self._event_timestamp(item[1])
                    or datetime.min.replace(tzinfo=timezone.utc),
                    item[0],
                ),
            )
        ]

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

    def _selector_string(self, deployment: dict[str, Any]) -> str:
        match_labels = (
            deployment.get("spec", {}).get("selector", {}).get("matchLabels", {}) or {}
        )
        if not match_labels:
            return "<deployment-selector>"
        return ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))

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

    def _replicaset_symptom(
        self, rs_name: str, rs: dict[str, Any]
    ) -> dict[str, Any] | None:
        desired = self._current_replicas(rs)
        available = self._available_replicas(rs)
        replica_failure = any(
            cond.get("type") == "ReplicaFailure"
            and str(cond.get("status", "")).strip().lower() == "true"
            for cond in rs.get("status", {}).get("conditions", []) or []
        )
        if desired <= 0:
            return None
        if available >= desired and not replica_failure:
            return None
        message = f"ReplicaSet '{rs_name}' still has only {available}/{desired} available replicas"
        if replica_failure:
            message += " and reports ReplicaFailure=True"
        return {
            "kind": "replicaset",
            "name": rs_name,
            "desired": desired,
            "available": available,
            "message": message,
        }

    def _deployment_symptom(
        self,
        deployment_name: str,
        deployment: dict[str, Any],
    ) -> dict[str, Any] | None:
        status = deployment.get("status", {}) or {}
        spec = deployment.get("spec", {}) or {}
        desired = self._as_int(spec.get("replicas", status.get("replicas", 0)), 0)
        available = self._as_int(status.get("availableReplicas"), 0)
        updated = self._as_int(status.get("updatedReplicas"), 0)
        if desired <= 0:
            return None
        if available >= desired and updated >= desired:
            return None
        return {
            "kind": "deployment",
            "name": deployment_name,
            "desired": desired,
            "available": available,
            "updated": updated,
            "message": (
                f"Deployment '{deployment_name}' still reports only {available}/{desired}"
                f" available replicas and {updated}/{desired} updated replicas"
            ),
        }

    def _action_sort_key(self, action: dict[str, Any]) -> datetime:
        return action.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc)

    def _scale_actions(
        self,
        timeline: Timeline,
        *,
        deployment_name: str | None,
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
            message = str(event.get("message", ""))
            message_lower = message.lower()
            names = {rs_name.lower()}
            if deployment_name:
                names.add(deployment_name.lower())

            if involved_name and involved_name not in names:
                if not any(name in message_lower for name in names):
                    continue

            actions.append(
                {
                    "rs_name": rs_name,
                    "direction": match.group(1).lower(),
                    "replicas": self._as_int(match.group(3), 0),
                    "timestamp": self._event_timestamp(event),
                    "message": message,
                }
            )

        actions.sort(key=self._action_sort_key)
        return actions

    def _collapse_actions(self, actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        collapsed: list[dict[str, Any]] = []
        for action in actions:
            if collapsed:
                previous = collapsed[-1]
                if (
                    previous["direction"] == action["direction"]
                    and previous["replicas"] == action["replicas"]
                ):
                    continue
            collapsed.append(action)
        return collapsed

    def _pattern_details(self, actions: list[dict[str, Any]]) -> dict[str, Any] | None:
        collapsed = self._collapse_actions(actions)
        if len(collapsed) < self.MIN_SCALE_EVENTS:
            return None

        directions = [action["direction"] for action in collapsed]
        if any(
            directions[idx] == directions[idx - 1] for idx in range(1, len(directions))
        ):
            return None

        up_count = sum(1 for action in collapsed if action["direction"] == "up")
        down_count = sum(1 for action in collapsed if action["direction"] == "down")
        if up_count < 2 or down_count < 2:
            return None

        unique_sizes = {action["replicas"] for action in collapsed}
        if len(unique_sizes) < 2:
            return None

        timestamps = [
            action["timestamp"]
            for action in collapsed
            if isinstance(action.get("timestamp"), datetime)
        ]
        if len(timestamps) < 2:
            return None
        duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        if duration_seconds < self.MIN_DURATION_SECONDS:
            return None

        direction_changes = len(collapsed) - 1
        if direction_changes < self.MIN_DIRECTION_CHANGES:
            return None

        display = [
            f"{action['direction']} to {action['replicas']}" for action in collapsed
        ]
        return {
            "collapsed": collapsed,
            "display": display,
            "up_count": up_count,
            "down_count": down_count,
            "direction_changes": direction_changes,
            "duration_seconds": duration_seconds,
            "unique_sizes": sorted(unique_sizes),
        }

    def _candidate_hpa(
        self,
        context: dict[str, Any],
        *,
        deployment_name: str | None,
        namespace: str,
    ) -> tuple[str, dict[str, Any]] | None:
        hpa_objs = context.get("objects", {}).get("hpa", {}) or {}
        if not hpa_objs:
            return None

        if deployment_name:
            for hpa_name, hpa in hpa_objs.items():
                if self._namespace(hpa) != namespace:
                    continue
                scale_target = hpa.get("spec", {}).get("scaleTargetRef", {}) or {}
                if str(scale_target.get("kind", "")).lower() != "deployment":
                    continue
                if str(scale_target.get("name", "")) == deployment_name:
                    return hpa_name, hpa

        in_namespace = [
            (name, hpa)
            for name, hpa in hpa_objs.items()
            if self._namespace(hpa) == namespace
        ]
        if len(in_namespace) == 1:
            return in_namespace[0]

        return None

    def _hpa_rescale_sequence(
        self,
        timeline: Timeline,
        *,
        hpa_name: str,
        deployment_name: str | None,
    ) -> dict[str, Any] | None:
        actions: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if self._event_reason(event) != "successfulrescale":
                continue

            source = self._source_component(event)
            if source and source not in self.HPA_COMPONENTS:
                continue

            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", "")).lower()
            message = str(event.get("message", ""))
            message_lower = message.lower()
            names = {hpa_name.lower()}
            if deployment_name:
                names.add(deployment_name.lower())

            if involved_name and involved_name not in names:
                if not any(name in message_lower for name in names):
                    continue

            size_match = self.HPA_SIZE_RE.search(message)
            if not size_match:
                continue
            actions.append(
                {
                    "size": self._as_int(size_match.group(1), 0),
                    "timestamp": self._event_timestamp(event),
                    "message": message,
                }
            )

        actions.sort(
            key=lambda item: item.get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        if len(actions) < 3:
            return None

        sizes: list[int] = []
        for action in actions:
            if not sizes or sizes[-1] != action["size"]:
                sizes.append(action["size"])

        if len(sizes) < 3:
            return None

        directions: list[str] = []
        for idx in range(1, len(sizes)):
            if sizes[idx] > sizes[idx - 1]:
                directions.append("up")
            elif sizes[idx] < sizes[idx - 1]:
                directions.append("down")

        if len(directions) < 2:
            return None
        if any(
            directions[idx] == directions[idx - 1] for idx in range(1, len(directions))
        ):
            return None

        return {
            "sizes": sizes,
            "direction_changes": len(directions),
        }

    def _best_candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        if (
            self._deployment_rollout_oscillation_rule._analyze_rollout(pod, context)
            is not None
        ):
            return None

        objects = context.get("objects", {}) or {}
        replicasets = objects.get("replicaset", {}) or {}
        if not replicasets:
            return None

        namespace = self._namespace(pod)
        deployments = objects.get("deployment", {}) or {}
        deployment_entry = self._candidate_deployment(pod, deployments, replicasets)
        deployment_name = None
        deployment = None
        workload_rs = replicasets
        if deployment_entry is not None:
            deployment_name, deployment = deployment_entry
            owned = self._owned_replicasets(
                deployment_name,
                self._namespace(deployment),
                replicasets,
            )
            if owned:
                workload_rs = owned

        if not workload_rs:
            return None

        actions = self._scale_actions(
            timeline,
            deployment_name=deployment_name,
            replicaset_names=set(workload_rs),
        )
        if len(actions) < self.MIN_SCALE_EVENTS:
            return None

        best: dict[str, Any] | None = None
        best_score = (-1, -1.0)
        for rs_name in workload_rs:
            rs_actions = [action for action in actions if action["rs_name"] == rs_name]
            pattern = self._pattern_details(rs_actions)
            if pattern is None:
                continue

            rs = workload_rs[rs_name]
            symptom = None
            if deployment_name and deployment:
                symptom = self._deployment_symptom(deployment_name, deployment)
            if symptom is None:
                symptom = self._replicaset_symptom(rs_name, rs)
            if symptom is None:
                continue

            score = (len(pattern["collapsed"]), pattern["duration_seconds"])
            if score > best_score:
                best_score = score
                best = {
                    "deployment_name": deployment_name,
                    "deployment": deployment,
                    "rs_name": rs_name,
                    "rs": rs,
                    "pattern": pattern,
                    "symptom": symptom,
                }

        if best is None:
            return None

        hpa_candidate = self._candidate_hpa(
            context,
            deployment_name=best["deployment_name"],
            namespace=namespace,
        )
        if hpa_candidate is not None:
            hpa_name, hpa = hpa_candidate
            hpa_sequence = self._hpa_rescale_sequence(
                timeline,
                hpa_name=hpa_name,
                deployment_name=best["deployment_name"],
            )
            if hpa_sequence is not None:
                best["hpa_name"] = hpa_name
                best["hpa"] = hpa
                best["hpa_sequence"] = hpa_sequence

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._best_candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._best_candidate(pod, context)
        if candidate is None:
            raise ValueError("ReplicaOscillation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        rs_name = candidate["rs_name"]
        pattern = candidate["pattern"]
        symptom = candidate["symptom"]
        minutes = pattern["duration_seconds"] / 60.0

        if symptom["kind"] == "deployment":
            desired = symptom["desired"]
            available = symptom["available"]
            updated = symptom["updated"]
            workload_symptom = (
                f"Deployment remains below stable capacity ({available}/{desired}"
                f" available, {updated}/{desired} updated) while replica targets keep"
                " reversing"
            )
            root_cause = (
                "Replica count is oscillating for the workload instead of converging"
            )
        else:
            desired = symptom["desired"]
            available = symptom["available"]
            workload_symptom = (
                f"ReplicaSet remains below stable capacity ({available}/{desired}"
                " available) while desired replica counts keep reversing"
            )
            root_cause = (
                "Replica count is oscillating for the workload instead of converging"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPLICA_SCALING_OSCILLATION_OBSERVED",
                    message=f"Timeline shows repeated scale reversals for ReplicaSet '{rs_name}'",
                    role="temporal_context",
                ),
                Cause(
                    code="REPLICA_OSCILLATION",
                    message="Replica count keeps alternating between scale-up and scale-down instead of settling on a stable desired size",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="SCALING_CONTROL_LOOP_THRASHING",
                    message="Controllers or autoscalers are repeatedly reversing replica decisions for the same workload",
                    role="control_loop",
                ),
                Cause(
                    code="WORKLOAD_CAPACITY_UNSTABLE",
                    message=workload_symptom,
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"ReplicaSet '{rs_name}' scaled as: {' -> '.join(pattern['display'])}",
            f"Scaling direction reversed {pattern['direction_changes']} times over {minutes:.1f} minutes",
            "The same ReplicaSet kept changing size instead of a clean one-way rollout handoff",
            symptom["message"],
        ]

        if candidate.get("hpa_sequence") and candidate.get("hpa_name"):
            hpa_sequence = candidate["hpa_sequence"]
            evidence.append(
                f"HPA '{candidate['hpa_name']}' also rescaled the workload back and forth as: {' -> '.join(str(size) for size in hpa_sequence['sizes'])}"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod belongs to a workload whose desired replica count kept reversing"
            ],
            f"replicaset:{rs_name}": [
                f"scaleUpEvents={pattern['up_count']}, scaleDownEvents={pattern['down_count']}",
                f"targetReplicaSizes={','.join(str(size) for size in pattern['unique_sizes'])}",
                f"availableReplicas={self._available_replicas(candidate['rs'])}/{self._current_replicas(candidate['rs'])}",
            ],
        }

        if symptom["kind"] == "deployment" and candidate.get("deployment_name"):
            deployment_name = candidate["deployment_name"]
            deployment = candidate["deployment"]
            object_evidence[f"deployment:{deployment_name}"] = [
                f"observedGeneration={self._as_int(deployment.get('status', {}).get('observedGeneration'), 0)}, generation={self._as_int(deployment.get('metadata', {}).get('generation'), 0)}",
                f"updatedReplicas={symptom['updated']}, availableReplicas={symptom['available']}, desiredReplicas={symptom['desired']}",
            ]

        if candidate.get("hpa_name") and candidate.get("hpa_sequence"):
            hpa_name = candidate["hpa_name"]
            hpa_sequence = candidate["hpa_sequence"]
            object_evidence[f"hpa:{hpa_name}"] = [
                f"SuccessfulRescale sizes alternated as {' -> '.join(str(size) for size in hpa_sequence['sizes'])}"
            ]
            scale_target = (
                candidate["hpa"].get("spec", {}).get("scaleTargetRef", {})
                if candidate.get("hpa")
                else {}
            )
            if scale_target.get("kind") and scale_target.get("name"):
                object_evidence[f"hpa:{hpa_name}"].append(
                    f"scaleTargetRef={scale_target.get('kind')}/{scale_target.get('name')}"
                )

        confidence = 0.91
        if candidate.get("hpa_sequence"):
            confidence = 0.94

        suggested_checks = [
            f"kubectl describe rs {rs_name}",
            "kubectl get events --sort-by=.lastTimestamp",
        ]
        if candidate.get("deployment_name"):
            suggested_checks.insert(
                0, f"kubectl describe deployment {candidate['deployment_name']}"
            )
            if candidate.get("deployment"):
                suggested_checks.append(
                    f"kubectl get rs -l {self._selector_string(candidate['deployment'])} -o wide"
                )
        if candidate.get("hpa_name"):
            suggested_checks.append(f"kubectl describe hpa {candidate['hpa_name']}")

        return {
            "root_cause": root_cause,
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "An HPA or other autoscaler is responding too aggressively and repeatedly reversing desired replica counts",
                "Manual or GitOps updates to spec.replicas are fighting with autoscaler-driven changes",
                "Conflicting controller inputs are alternately scaling the same workload up and down before it stabilizes",
                "Replica health never stabilizes long enough for the workload to converge on one desired size",
            ],
            "suggested_checks": suggested_checks,
        }
