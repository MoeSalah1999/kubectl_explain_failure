from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ControllerOwnershipConflictChainRule(FailureRule):
    """
    Detects a rollout incident where a real controller ownership conflict is not
    just present, but is clearly the reason the workload management chain has
    stalled.

    Real-world behavior:
    - unsupported selector overlap or label drift can leave a Pod owned by one
      ReplicaSet while another active ReplicaSet also tries to reconcile it
    - in production this usually matters when the conflict is sustained long
      enough to degrade rollout convergence, not when there is a single brief
      warning event
    - the strongest signal is an ownership conflict tied to the same ReplicaSet
      set that is also participating in a stalled Deployment rollout
    """

    name = "ControllerOwnershipConflictChain"
    category = "Compound"
    priority = 62
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["replicaset"],
        "context": ["timeline"],
        "optional_objects": ["deployment"],
    }
    blocks = [
        "ReplicaSetOwnershipConflict",
        "DeploymentRolloutStalled",
        "DeploymentProgressDeadlineExceeded",
        "DeploymentReplicaMismatch",
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
        "OwnerBlockedPod",
    ]

    CACHE_KEY = "_controller_ownership_conflict_chain_candidate"
    WINDOW_MINUTES = 30
    MIN_RELEVANT_EVENTS = 3
    MIN_INCIDENT_SPAN_SECONDS = 300
    CONTROLLER_COMPONENTS = {
        "deployment-controller",
        "deploymentcontroller",
        "replicaset-controller",
        "kube-controller-manager",
    }
    ROLLOUT_REASONS = {
        "scalingreplicaset",
        "failedcreate",
        "failedupdate",
        "successfulcreate",
    }

    def __init__(self) -> None:
        from kubectl_explain_failure.rules.base.controllers.replicaset_ownership_conflict import (
            ReplicaSetOwnershipConflictRule,
        )
        from kubectl_explain_failure.rules.compound.controllers.deployment_rollout_stalled import (
            DeploymentRolloutStalledRule,
        )

        self._conflict_rule = ReplicaSetOwnershipConflictRule()
        self._rollout_rule = DeploymentRolloutStalledRule()

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

    def _span_seconds(self, events: list[dict[str, Any]]) -> float:
        timestamps = [self._event_timestamp(event) for event in events]
        usable = [ts for ts in timestamps if ts is not None]
        if len(usable) < 2:
            return 0.0
        return (max(usable) - min(usable)).total_seconds()

    def _deployment_name_for_object(self, obj: dict[str, Any]) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == "deployment" and ref.get("name"):
                return str(ref["name"])
        return None

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict) and self._namespace(direct) == namespace:
            return direct

        for obj in objects.get(kind, {}).values():
            if not isinstance(obj, dict):
                continue
            if obj.get("metadata", {}).get("name") != name:
                continue
            if self._namespace(obj) != namespace:
                continue
            return obj
        return None

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

        progress_condition = None
        for cond in status.get("conditions", []) or []:
            if cond.get("type") == "Progressing":
                progress_condition = cond
                break

        deadline_exceeded = bool(
            progress_condition
            and str(progress_condition.get("reason", "")) == "ProgressDeadlineExceeded"
            and str(progress_condition.get("status", "")).strip().lower() == "false"
        )

        if desired <= 0:
            return None
        if available >= desired and not deadline_exceeded:
            return None

        message = f"Deployment '{deployment_name}' remains at {available}/{desired} available replicas"
        if updated or desired:
            message += f" with only {updated}/{desired} updated replicas"
        if deadline_exceeded:
            message += " and ProgressDeadlineExceeded"

        return {
            "kind": "deployment",
            "name": deployment_name,
            "desired": desired,
            "available": available,
            "updated": updated,
            "deadline_exceeded": deadline_exceeded,
            "message": message,
            "progress_message": (
                str(progress_condition.get("message", "")).strip()
                if isinstance(progress_condition, dict)
                else ""
            ),
        }

    def _replicaset_symptom(
        self,
        rs_name: str,
        rs: dict[str, Any],
    ) -> dict[str, Any] | None:
        status = rs.get("status", {}) or {}
        desired = self._current_replicas(rs)
        available = self._available_replicas(rs)
        replica_failure = any(
            cond.get("type") == "ReplicaFailure"
            and str(cond.get("status", "")).strip().lower() == "true"
            for cond in status.get("conditions", []) or []
        )

        if desired <= 0:
            return None
        if available >= desired and not replica_failure:
            return None

        message = f"ReplicaSet '{rs_name}' remains at {available}/{desired} available replicas"
        if replica_failure:
            message += " and reports ReplicaFailure=True"

        return {
            "kind": "replicaset",
            "name": rs_name,
            "desired": desired,
            "available": available,
            "replica_failure": replica_failure,
            "message": message,
        }

    def _pod_symptom(self, pod: dict[str, Any]) -> str | None:
        phase = str(pod.get("status", {}).get("phase", "") or "")
        pod_name = str(pod.get("metadata", {}).get("name", "<pod>") or "<pod>")
        if phase == "Pending":
            return f"Pod '{pod_name}' is still Pending while controller ownership remains contested"

        for cond in pod.get("status", {}).get("conditions", []) or []:
            if cond.get("type") == "Ready" and str(cond.get("status", "")).lower() in {
                "false",
                "unknown",
            }:
                return (
                    f"Pod '{pod_name}' is not Ready while the conflicting controller"
                    " paths are still active"
                )

        for container in pod.get("status", {}).get("containerStatuses", []) or []:
            if container.get("ready") is False:
                return (
                    f"Pod '{pod_name}' has unready containers while controller"
                    " ownership is unresolved"
                )

        return None

    def _incident_events(
        self,
        timeline: Timeline,
        *,
        minutes: int,
        names: set[str],
    ) -> list[dict[str, Any]]:
        lowered_names = {name.lower() for name in names if name}
        relevant: list[dict[str, Any]] = []

        for event in timeline.events_within_window(minutes):
            source = self._source_component(event)
            reason = self._event_reason(event)
            message = self._event_message(event)
            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", "")).lower()

            if source and source not in self.CONTROLLER_COMPONENTS:
                if reason not in self.ROLLOUT_REASONS:
                    continue

            if involved_name in lowered_names or any(
                name in message for name in lowered_names
            ):
                relevant.append(event)

        return self._ordered_events(relevant)

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        conflict = self._conflict_rule._candidate_conflict(pod, context)
        if conflict is None:
            return None

        objects = context.get("objects", {}) or {}
        namespace = self._namespace(pod)
        conflicting_rs = [name for name in conflict.get("conflicting_rs", []) if name]
        if not conflicting_rs:
            return None

        rollout_candidate = self._rollout_rule._analyze_rollout(pod, context)
        rollout_overlap = False
        rollout_rs_names: set[str] = set()
        if rollout_candidate is not None:
            rollout_rs_names = {
                rollout_candidate["new_rs_name"],
                *(name for name, _ in rollout_candidate["older_rs"]),
            }
            rollout_overlap = bool(rollout_rs_names & set(conflicting_rs))
            if not rollout_overlap:
                rollout_candidate = None

        owner_deployments: dict[str, str] = {}
        for rs_name in conflicting_rs:
            rs = objects.get("replicaset", {}).get(rs_name)
            if not isinstance(rs, dict):
                continue
            deployment_name = self._deployment_name_for_object(rs)
            if deployment_name:
                owner_deployments[rs_name] = deployment_name

        deployment_symptom = None
        if rollout_candidate is not None:
            deployment_symptom = self._deployment_symptom(
                rollout_candidate["deployment_name"],
                rollout_candidate["deployment"],
            )

        if deployment_symptom is None:
            deployment_names = list(dict.fromkeys(owner_deployments.values()))
            for deployment_name in deployment_names:
                deployment = self._find_named_object(
                    objects,
                    "deployment",
                    deployment_name,
                    namespace,
                )
                if deployment is None:
                    continue
                deployment_symptom = self._deployment_symptom(
                    deployment_name,
                    deployment,
                )
                if deployment_symptom is not None:
                    break

        rs_symptom = None
        if deployment_symptom is None:
            for rs_name in conflicting_rs:
                rs = objects.get("replicaset", {}).get(rs_name)
                if not isinstance(rs, dict):
                    continue
                rs_symptom = self._replicaset_symptom(rs_name, rs)
                if rs_symptom is not None:
                    break

        if deployment_symptom is None and rs_symptom is None:
            return None

        incident_window_minutes = self.WINDOW_MINUTES
        if rollout_candidate is not None:
            incident_window_minutes = max(
                incident_window_minutes,
                (rollout_candidate["progress_deadline_seconds"] + 59) // 60 + 10,
            )

        tracked_names = {
            *conflicting_rs,
            *owner_deployments.values(),
        }
        if rollout_candidate is not None:
            tracked_names.add(rollout_candidate["deployment_name"])
            tracked_names.update(rollout_rs_names)

        relevant_events = self._incident_events(
            timeline,
            minutes=incident_window_minutes,
            names=tracked_names,
        )
        if not relevant_events:
            return None

        conflict_events = [
            event
            for event in relevant_events
            if any(
                marker in self._event_message(event)
                for marker in self._conflict_rule.CONFLICT_MARKERS
            )
        ]
        if not conflict_events:
            return None

        span_seconds = self._span_seconds(relevant_events)
        if rollout_candidate is None:
            if (
                len(conflict_events) < 2
                and span_seconds < self.MIN_INCIDENT_SPAN_SECONDS
            ):
                return None
            if len(relevant_events) < self.MIN_RELEVANT_EVENTS:
                return None

        controller_symptom = deployment_symptom or rs_symptom
        if controller_symptom is None:
            return None

        representative_event = conflict_events[-1]
        representative_message = (
            str(representative_event.get("message", "")).strip()
            or str(conflict.get("conflict_message", "")).strip()
        )
        if not representative_message:
            return None

        return {
            "conflict": conflict,
            "conflicting_rs": conflicting_rs,
            "owner_deployments": owner_deployments,
            "controller_symptom": controller_symptom,
            "rollout_candidate": rollout_candidate,
            "relevant_event_count": len(relevant_events),
            "conflict_event_count": len(conflict_events),
            "span_seconds": span_seconds,
            "representative_message": representative_message,
            "pod_symptom": self._pod_symptom(pod),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError(
                "ControllerOwnershipConflictChain explain() called without match"
            )

        pod_name = str(pod.get("metadata", {}).get("name", "<pod>") or "<pod>")
        conflict = candidate["conflict"]
        owner_rs = conflict["owner_rs"]
        primary_conflict = conflict.get("primary_conflict") or "<unknown>"
        controller_symptom = candidate["controller_symptom"]
        span_minutes = candidate["span_seconds"] / 60.0

        if conflict["owner_selector_matches"]:
            conflict_detail = (
                f"Pod '{pod_name}' matches multiple active ReplicaSets during the same"
                f" rollout incident: {', '.join(conflict['matching_rs'])}"
            )
        else:
            conflict_detail = (
                f"Pod '{pod_name}' is owned by ReplicaSet '{owner_rs}' but its labels"
                f" now match active ReplicaSet '{primary_conflict}' instead"
            )

        if controller_symptom["kind"] == "deployment":
            desired = controller_symptom["desired"]
            available = controller_symptom["available"]
            workload_symptom = (
                f"Workload rollout remains below target availability ({available}/{desired})"
                " while controller ownership is unresolved"
            )
            root_cause = (
                "Controller ownership conflict between active ReplicaSets is stalling"
                " the workload rollout"
            )
        else:
            desired = controller_symptom["desired"]
            available = controller_symptom["available"]
            workload_symptom = (
                f"ReplicaSet reconciliation remains degraded at {available}/{desired}"
                " available replicas while ownership conflict persists"
            )
            root_cause = (
                "Controller ownership conflict between active ReplicaSets is blocking"
                " ReplicaSet reconciliation"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFLICTING_CONTROLLER_PATHS",
                    message="Multiple active controller paths are targeting the same Pod identity during rollout",
                    role="controller_context",
                ),
                Cause(
                    code="CONTROLLER_OWNERSHIP_CONFLICT",
                    message="Pod labels and controller ownership metadata disagree about which ReplicaSet should manage the Pod",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTROLLER_RECONCILIATION_CHAIN_STALLED",
                    message="Controller reconciliation cannot converge because rollout and adoption decisions keep colliding",
                    role="controller_intermediate",
                ),
                Cause(
                    code="WORKLOAD_MANAGEMENT_IMPAIRED",
                    message=workload_symptom,
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            conflict_detail,
            (
                f"Recent controller activity spans {span_minutes:.1f} minutes across"
                f" {candidate['relevant_event_count']} rollout-related events with"
                f" {candidate['conflict_event_count']} ownership conflict signal(s)"
            ),
            f"Representative ownership conflict: {candidate['representative_message']}",
            controller_symptom["message"],
        ]
        if candidate["pod_symptom"]:
            evidence.append(candidate["pod_symptom"])

        object_evidence = {
            f"pod:{pod_name}": [conflict_detail],
            f"replicaset:{owner_rs}": [
                "Current controller owner recorded in ownerReferences"
            ],
        }
        if primary_conflict and primary_conflict != "<unknown>":
            object_evidence[f"replicaset:{primary_conflict}"] = [
                "Competing active ReplicaSet also targets the Pod during rollout"
            ]

        object_evidence[
            f"{controller_symptom['kind']}:{controller_symptom['name']}"
        ] = [controller_symptom["message"]]
        if controller_symptom["kind"] == "deployment" and controller_symptom.get(
            "deadline_exceeded"
        ):
            object_evidence[f"deployment:{controller_symptom['name']}"].append(
                "Progressing=False (ProgressDeadlineExceeded)"
            )
        progress_message = controller_symptom.get("progress_message")
        if controller_symptom["kind"] == "deployment" and progress_message:
            object_evidence[f"deployment:{controller_symptom['name']}"].append(
                progress_message
            )

        confidence = 0.97 if candidate["rollout_candidate"] is not None else 0.95
        if controller_symptom["kind"] == "deployment" and controller_symptom.get(
            "deadline_exceeded"
        ):
            confidence = 0.98

        return {
            "root_cause": root_cause,
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "A rollout revision or copied controller introduced a selector that overlaps with another active ReplicaSet",
                "Manual label or ownerReference edits left an existing Pod owned by one ReplicaSet while another controller revision now also matches it",
                "GitOps or automation reapplied controller objects with broadened selectors, causing competing ownership during rollout",
                "The workload cannot converge until each Pod is matched by exactly one active controller path",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Compare ReplicaSet selectors, template labels, and ownerReferences with `kubectl get rs -o yaml`",
                "Review recent deployment and ReplicaSet controller events around the conflicting rollout window",
                (
                    f"kubectl rollout status deployment {controller_symptom['name']}"
                    if controller_symptom["kind"] == "deployment"
                    else f"kubectl describe rs {controller_symptom['name']}"
                ),
            ],
        }
