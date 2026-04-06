from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class ReplicaSetOwnershipConflictRule(FailureRule):
    """
    Detects unsupported ownership contention where more than one active
    ReplicaSet can claim the same Pod.

    Real-world behavior:
    - ReplicaSets are expected to have non-overlapping selectors in a namespace
    - manual selector edits, copied manifests, or stale ownerReferences can let
      two active ReplicaSets contend for the same Pod during rollout
    - this commonly shows up as repeated controller activity from multiple
      ReplicaSets plus create/adopt failures or stalled reconciliation
    """

    name = "ReplicaSetOwnershipConflict"
    category = "Controller"
    priority = 58
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["replicaset"],
        "context": ["timeline"],
    }
    blocks = [
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
        "DeploymentReplicaMismatch",
    ]

    WINDOW_MINUTES = 20
    CONTROLLER_COMPONENTS = {
        "deploymentcontroller",
        "deployment-controller",
        "replicaset-controller",
    }
    CONFLICT_MARKERS = (
        "already has controller reference",
        "already owned by",
        "controller ref",
        "cannot adopt",
        "adopt",
        "overlap",
        "selector overlaps",
    )

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _match_selector(
        self,
        selector: dict[str, Any] | None,
        labels: dict[str, str],
    ) -> bool:
        if selector is None:
            return False
        if not selector:
            return True

        for key, expected in (selector.get("matchLabels", {}) or {}).items():
            if labels.get(key) != expected:
                return False

        for expr in selector.get("matchExpressions", []) or []:
            key = expr.get("key")
            operator = expr.get("operator")
            values = expr.get("values", []) or []
            actual = labels.get(key)

            if operator == "In" and actual not in values:
                return False
            if operator == "NotIn" and actual in values:
                return False
            if operator == "Exists" and actual is None:
                return False
            if operator == "DoesNotExist" and actual is not None:
                return False

        return True

    def _active_replicaset(self, rs: dict[str, Any]) -> bool:
        spec_replicas = rs.get("spec", {}).get("replicas", 0) or 0
        status_replicas = rs.get("status", {}).get("replicas", 0) or 0
        return int(spec_replicas) > 0 or int(status_replicas) > 0

    def _owned_replicaset(self, pod: dict[str, Any]) -> str | None:
        owners = pod.get("metadata", {}).get("ownerReferences", []) or []
        controller_owned = [
            ref
            for ref in owners
            if str(ref.get("kind", "")).lower() == "replicaset"
            and ref.get("controller") is True
        ]
        if controller_owned:
            return str(controller_owned[0].get("name", ""))
        for ref in owners:
            if str(ref.get("kind", "")).lower() == "replicaset":
                return str(ref.get("name", ""))
        return None

    def _namespace_match(self, obj: dict[str, Any], namespace: str) -> bool:
        return obj.get("metadata", {}).get("namespace", "default") == namespace

    def _candidate_conflict(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        labels = pod.get("metadata", {}).get("labels", {}) or {}
        if not labels:
            return None

        namespace = pod.get("metadata", {}).get("namespace", "default")
        rs_objs = context.get("objects", {}).get("replicaset", {})
        owner_rs = self._owned_replicaset(pod)
        if not rs_objs or not owner_rs:
            return None

        matching_rs: list[str] = []
        owner_selector_matches = False

        for rs_name, rs in rs_objs.items():
            if not isinstance(rs, dict) or not self._namespace_match(rs, namespace):
                continue
            if not self._active_replicaset(rs):
                continue
            selector = rs.get("spec", {}).get("selector")
            if not self._match_selector(selector, labels):
                if rs_name == owner_rs:
                    owner_selector_matches = False
                continue

            matching_rs.append(rs_name)
            if rs_name == owner_rs:
                owner_selector_matches = True

        conflicting_rs = sorted(set(matching_rs))
        if owner_rs not in conflicting_rs and owner_selector_matches is False:
            conflicting_rs = [owner_rs] + conflicting_rs

        if owner_rs in matching_rs and len(matching_rs) < 2:
            return None
        if owner_rs not in matching_rs and not matching_rs:
            return None

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        mentioned_rs: set[str] = set()
        conflict_message = None
        rollout_events = 0

        for event in recent:
            component = self._source_component(event)
            message = self._event_message(event)
            reason = self._event_reason(event)
            if component in self.CONTROLLER_COMPONENTS or reason in {
                "scalingreplicaset",
                "failedcreate",
                "successfulcreate",
            }:
                for rs_name in conflicting_rs:
                    if rs_name.lower() in message:
                        mentioned_rs.add(rs_name)
                        rollout_events += 1
                if conflict_message is None and any(
                    marker in message for marker in self.CONFLICT_MARKERS
                ):
                    conflict_message = str(event.get("message", ""))

        if conflict_message is None and len(mentioned_rs) < 2:
            return None

        primary_conflict = [name for name in matching_rs if name != owner_rs]

        return {
            "owner_rs": owner_rs,
            "matching_rs": matching_rs,
            "conflicting_rs": conflicting_rs,
            "primary_conflict": primary_conflict[0] if primary_conflict else None,
            "owner_selector_matches": owner_selector_matches,
            "rollout_events": rollout_events,
            "conflict_message": conflict_message,
        }

    def matches(self, pod, events, context) -> bool:
        return self._candidate_conflict(pod, context) is not None

    def explain(self, pod, events, context):
        candidate = self._candidate_conflict(pod, context)
        if candidate is None:
            raise ValueError(
                "ReplicaSetOwnershipConflict explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        owner_rs = candidate["owner_rs"]
        primary_conflict = candidate["primary_conflict"] or "<unknown>"
        matching_rs = candidate["matching_rs"]

        if candidate["owner_selector_matches"]:
            conflict_detail = f"Pod labels match multiple active ReplicaSets: {', '.join(matching_rs)}"
        else:
            conflict_detail = f"Pod is owned by ReplicaSet '{owner_rs}' but its labels now match active ReplicaSet '{primary_conflict}' instead"

        chain = CausalChain(
            causes=[
                Cause(
                    code="MULTIPLE_REPLICASETS_ACTIVE",
                    message="Multiple active ReplicaSets are reconciling the same rollout window",
                    role="controller_context",
                ),
                Cause(
                    code="REPLICASET_OWNERSHIP_CONFLICT",
                    message="ReplicaSet selectors or owner metadata allow more than one controller path to claim the same Pod",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="REPLICASET_RECONCILIATION_CONTENDED",
                    message="ReplicaSet reconciliation becomes unstable because ownership and adoption are ambiguous",
                    role="controller_intermediate",
                ),
                Cause(
                    code="ROLLOUT_PROGRESS_IMPAIRED",
                    message="Controller rollout progress is impaired by conflicting ReplicaSet ownership",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            conflict_detail,
            f"Recent controller timeline shows activity for conflicting ReplicaSets within {self.WINDOW_MINUTES} minutes",
        ]
        if candidate["conflict_message"]:
            evidence.append(
                f"Representative conflict signal: {candidate['conflict_message']}"
            )

        object_evidence = {
            f"pod:{pod_name}": [conflict_detail],
            f"replicaset:{owner_rs}": ["Current Pod owner in ownerReferences"],
        }
        if primary_conflict:
            object_evidence[f"replicaset:{primary_conflict}"] = [
                "Also matches Pod labels during active reconciliation"
            ]

        return {
            "root_cause": "Overlapping ReplicaSet ownership is causing controller conflict",
            "confidence": 0.96 if candidate["conflict_message"] else 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Two ReplicaSets in the same namespace have overlapping selectors",
                "A Pod was manually relabeled or ownerReferences were edited, so ReplicaSet adoption is now ambiguous",
                "A rollout or copied manifest introduced a ReplicaSet selector that is broader than intended",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Compare ReplicaSet selectors and template labels with `kubectl get rs -o yaml`",
                "Ensure only one active ReplicaSet selector matches the Pod labels in this namespace",
                "Review recent rollout changes for manual selector or ownerReference edits",
            ],
        }
