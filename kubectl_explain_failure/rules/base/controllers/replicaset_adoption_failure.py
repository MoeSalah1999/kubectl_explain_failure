from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ReplicaSetAdoptionFailureRule(FailureRule):
    """
    Detects a ReplicaSet that should adopt a matching orphan Pod but repeatedly
    fails to write controller ownership.

    Real-world interpretation:
    - the Pod has labels that match one active ReplicaSet in the namespace
    - the Pod does not currently have a controlling ReplicaSet ownerReference
    - ReplicaSet controller events explicitly report adoption/update failures
    - desired rollout state remains degraded because reconciliation cannot
      complete until ownership is established
    """

    name = "ReplicaSetAdoptionFailure"
    category = "Controller"
    priority = 57
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["replicaset"],
        "context": ["timeline"],
        "optional_objects": ["deployment"],
    }
    blocks = [
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
        "DeploymentReplicaMismatch",
    ]

    WINDOW_MINUTES = 20
    CONTROLLER_COMPONENTS = {
        "replicaset-controller",
        "deploymentcontroller",
        "deployment-controller",
        "kube-controller-manager",
    }
    ADOPTION_MARKERS = (
        "cannot adopt",
        "failed to adopt",
        "adopt pod",
        "adoption",
        "ownerreferences for adoption",
        "failed to update ownerreferences",
    )

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _ordered_recent(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_ts(item[1]) is None else 0,
                    self._event_ts(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

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
        return (
            self._as_int(rs.get("spec", {}).get("replicas"), 0) > 0
            or self._as_int(rs.get("status", {}).get("replicas"), 0) > 0
        )

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _has_controller_owner(self, pod: dict[str, Any]) -> bool:
        for ref in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if ref.get("controller") is True:
                return True
        return False

    def _matching_replicasets(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[tuple[str, dict[str, Any]]]:
        labels = pod.get("metadata", {}).get("labels", {}) or {}
        namespace = self._namespace(pod)
        matches: list[tuple[str, dict[str, Any]]] = []
        for rs_name, rs in context.get("objects", {}).get("replicaset", {}).items():
            if not isinstance(rs, dict):
                continue
            if self._namespace(rs) != namespace:
                continue
            if not self._active_replicaset(rs):
                continue
            if self._match_selector(rs.get("spec", {}).get("selector"), labels):
                matches.append((rs_name, rs))
        return matches

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict):
            if self._namespace(direct) == namespace:
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

    def _deployment_symptom(
        self,
        rs: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, str] | None:
        namespace = self._namespace(rs)
        for ref in rs.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() != "deployment" or not ref.get("name"):
                continue
            deployment_name = str(ref["name"])
            deployment = self._find_named_object(
                context.get("objects", {}),
                "deployment",
                deployment_name,
                namespace,
            )
            if deployment is None:
                continue
            status = deployment.get("status", {}) or {}
            desired = self._as_int(
                status.get("replicas", deployment.get("spec", {}).get("replicas", 0)),
                0,
            )
            available = self._as_int(status.get("availableReplicas"), 0)
            updated = self._as_int(status.get("updatedReplicas"), 0)
            if desired > 0 and available < desired:
                return {
                    "kind": "deployment",
                    "name": deployment_name,
                    "message": f"Deployment '{deployment_name}' remains at {available}/{desired} available replicas while only {updated}/{desired} replicas are updated",
                }
        return None

    def _replicaset_symptom(
        self, rs_name: str, rs: dict[str, Any]
    ) -> dict[str, str] | None:
        status = rs.get("status", {}) or {}
        conditions = status.get("conditions", []) or []
        if any(
            cond.get("type") == "ReplicaFailure"
            and str(cond.get("status", "")).lower() == "true"
            for cond in conditions
        ):
            return {
                "kind": "replicaset",
                "name": rs_name,
                "message": f"ReplicaSet '{rs_name}' reports ReplicaFailure=True while matching orphan Pods remain unadopted",
            }
        available = self._as_int(status.get("availableReplicas"), 0)
        desired = self._as_int(
            status.get("replicas", rs.get("spec", {}).get("replicas", 0)),
            0,
        )
        if desired > 0 and available < desired:
            return {
                "kind": "replicaset",
                "name": rs_name,
                "message": f"ReplicaSet '{rs_name}' remains at {available}/{desired} available replicas while adoption is failing",
            }
        return None

    def _adoption_events(
        self,
        pod_name: str,
        rs_name: str,
        ordered_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for event in ordered_events:
            component = self._source_component(event)
            if component and component not in self.CONTROLLER_COMPONENTS:
                continue
            message = self._event_message(event)
            reason = self._event_reason(event)
            if pod_name.lower() not in message or rs_name.lower() not in message:
                continue
            if not any(marker in message for marker in self.ADOPTION_MARKERS):
                continue
            if reason not in {"failedcreate", "failedupdate", "failed", "sync"}:
                continue
            matches.append(event)
        return matches

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None
        if self._has_controller_owner(pod):
            return None

        matches = self._matching_replicasets(pod, context)
        if len(matches) != 1:
            return None

        rs_name, rs = matches[0]
        ordered_events = self._ordered_recent(timeline)
        pod_name = str(pod.get("metadata", {}).get("name", "") or "")
        if not pod_name:
            return None

        adoption_events = self._adoption_events(pod_name, rs_name, ordered_events)
        if not adoption_events:
            return None

        symptom = self._deployment_symptom(rs, context) or self._replicaset_symptom(
            rs_name, rs
        )
        if symptom is None:
            return None

        latest_event = adoption_events[-1]
        return {
            "rs_name": rs_name,
            "symptom": symptom,
            "event_count": len(adoption_events),
            "representative_message": str(latest_event.get("message", "")).strip(),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop("_replicaset_adoption_failure_candidate", None)
            return False
        context["_replicaset_adoption_failure_candidate"] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(
            "_replicaset_adoption_failure_candidate"
        ) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError("ReplicaSetAdoptionFailure explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        rs_name = candidate["rs_name"]
        symptom = candidate["symptom"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="ORPHAN_POD_MATCHES_REPLICASET",
                    message="A matching Pod exists without a controlling ReplicaSet ownerReference, so ReplicaSet adoption is expected",
                    role="controller_context",
                ),
                Cause(
                    code="REPLICASET_ADOPTION_FAILED",
                    message="ReplicaSet repeatedly failed to write ownership while attempting to adopt the matching Pod",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="REPLICASET_RECONCILIATION_STALLED",
                    message="ReplicaSet reconciliation remains degraded because matching orphan Pods are not being adopted successfully",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "ReplicaSet failed to adopt a matching orphan Pod",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Pod '{pod_name}' has no controlling ownerReference but matches active ReplicaSet '{rs_name}'",
                f"Observed {candidate['event_count']} recent ReplicaSet adoption failure event(s) within {self.WINDOW_MINUTES} minutes",
                f"Representative adoption failure: {candidate['representative_message']}",
                f"Reconciliation symptom: {symptom['message']}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is orphaned from controller ownership but still matches a live ReplicaSet selector"
                ],
                f"replicaset:{rs_name}": [
                    candidate["representative_message"],
                ],
                f"{symptom['kind']}:{symptom['name']}": [
                    symptom["message"],
                ],
            },
            "likely_causes": [
                "ReplicaSet controller hit repeated optimistic-lock or API update conflicts while trying to write ownerReferences",
                "Admission or policy machinery blocked ownerReference updates during ReplicaSet adoption",
                "A manually created or orphaned Pod still matches the ReplicaSet selector but cannot be cleanly adopted",
                "Concurrent metadata mutation on the Pod is preventing ReplicaSet adoption from converging",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl describe rs {rs_name}",
                "Inspect ownerReferences, labels, and recent ReplicaSet controller events on the orphan Pod",
                "Review admission/policy controllers or metadata mutators that may be rewriting the Pod during adoption",
            ],
        }
