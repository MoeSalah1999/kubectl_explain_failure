from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class HPAInvalidTargetReferenceRule(FailureRule):
    """
    Detects an HPA whose scaleTargetRef no longer resolves to a valid scalable
    workload for this incident.

    Real-world behavior:
    - Kubernetes usually surfaces this as AbleToScale=False with reason
      FailedGetScale and warning events from horizontal-pod-autoscaler
    - this commonly happens after workload renames, stale GitOps manifests, or
      an HPA pointing at a kind/resource that does not expose the scale
      subresource
    - for this pod-centric engine, we only associate the HPA to the pod when
      the namespace/workload relationship is strong enough to avoid random
      cross-namespace autoscaler matches
    """

    name = "HPAInvalidTargetReference"
    category = "Controller"
    priority = 53
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["hpa"],
        "optional_objects": ["deployment", "statefulset", "replicaset"],
    }

    WINDOW_MINUTES = 20
    CACHE_KEY = "_hpa_invalid_target_reference_candidate"
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    FAILED_GET_SCALE_REASONS = {
        "failedgetscale",
    }
    FAILED_GET_SCALE_MARKERS = (
        "unable to get the target's current scale",
        "not found",
        "no matches for kind",
        "the server could not find the requested resource",
        "does not implement the scale subresource",
        "failed to get scale",
        "could not find the requested resource",
    )
    KIND_TO_OBJECT_KEY = {
        "deployment": "deployment",
        "statefulset": "statefulset",
        "replicaset": "replicaset",
        "replicationcontroller": "replicationcontroller",
    }

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _reason(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _owner_ref(self, obj: dict[str, Any], kind: str) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
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
            metadata = obj.get("metadata", {})
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", "default") != namespace:
                continue
            return obj
        return None

    def _pod_workload_ref(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, str] | None:
        namespace = self._namespace(pod)
        objects = context.get("objects", {}) or {}

        deployment_name = self._owner_ref(pod, "Deployment")
        if deployment_name:
            return {
                "kind": "Deployment",
                "name": deployment_name,
                "namespace": namespace,
            }

        statefulset_name = self._owner_ref(pod, "StatefulSet")
        if statefulset_name:
            return {
                "kind": "StatefulSet",
                "name": statefulset_name,
                "namespace": namespace,
            }

        rs_name = self._owner_ref(pod, "ReplicaSet")
        if rs_name:
            rs_obj = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs_obj is not None:
                deployment_name = self._owner_ref(rs_obj, "Deployment")
                if deployment_name:
                    return {
                        "kind": "Deployment",
                        "name": deployment_name,
                        "namespace": namespace,
                    }
            return {
                "kind": "ReplicaSet",
                "name": rs_name,
                "namespace": namespace,
            }

        return None

    def _normalize_name(self, value: str) -> str:
        return (
            value.lower()
            .replace("-hpa", "")
            .replace("hpa-", "")
            .replace("_", "-")
            .strip("-")
        )

    def _name_related(self, left: str, right: str) -> bool:
        if not left or not right:
            return False
        left_norm = self._normalize_name(left)
        right_norm = self._normalize_name(right)
        return (
            left_norm == right_norm
            or left_norm.startswith(right_norm)
            or right_norm.startswith(left_norm)
        )

    def _is_false(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"

    def _looks_failed_get_scale(self, *, reason: str, message: str) -> bool:
        reason_norm = self._reason(reason)
        message_norm = message.lower()
        if reason_norm in self.FAILED_GET_SCALE_REASONS:
            return True
        return any(marker in message_norm for marker in self.FAILED_GET_SCALE_MARKERS)

    def _failed_get_scale_condition(self, hpa: dict[str, Any]) -> dict[str, str] | None:
        for condition in hpa.get("status", {}).get("conditions", []) or []:
            cond_type = str(condition.get("type", ""))
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            if cond_type != "AbleToScale":
                continue
            if not self._is_false(condition.get("status")):
                continue
            if not self._looks_failed_get_scale(reason=reason, message=message):
                continue
            return {
                "type": cond_type,
                "reason": reason or "<unknown>",
                "message": message or "HPA cannot resolve its current scale target",
            }
        return None

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_targets_hpa(
        self,
        event: dict[str, Any],
        *,
        hpa_name: str,
        namespace: str,
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        if isinstance(involved, dict) and involved:
            involved_kind = str(involved.get("kind", "")).lower()
            involved_name = str(involved.get("name", ""))
            involved_namespace = str(involved.get("namespace", namespace))
            if involved_namespace != namespace:
                return False
            if involved_kind and involved_kind != "horizontalpodautoscaler":
                return False
            if involved_name and involved_name != hpa_name:
                return False
            return True

        return hpa_name.lower() in self._message(event.get("message")).lower()

    def _recent_failed_get_scale_events(
        self,
        timeline: Timeline | None,
        *,
        hpa_name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        if timeline is None:
            return []

        results: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            source = self._source_component(event)
            if source and source not in self.HPA_COMPONENTS:
                continue
            if not self._event_targets_hpa(
                event, hpa_name=hpa_name, namespace=namespace
            ):
                continue

            reason = self._message(event.get("reason"))
            message = self._message(event.get("message"))
            if not self._looks_failed_get_scale(reason=reason, message=message):
                continue
            results.append(event)

        results.sort(
            key=lambda event: self._event_ts(event)
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return results

    def _target_ref(self, hpa: dict[str, Any], namespace: str) -> dict[str, str]:
        target = hpa.get("spec", {}).get("scaleTargetRef", {}) or {}
        return {
            "apiVersion": str(target.get("apiVersion", "")),
            "kind": str(target.get("kind", "")),
            "name": str(target.get("name", "")),
            "namespace": namespace,
        }

    def _target_exists(
        self, context: dict[str, Any], target_ref: dict[str, str]
    ) -> bool:
        kind_key = self.KIND_TO_OBJECT_KEY.get(target_ref["kind"].lower())
        if not kind_key or not target_ref["name"]:
            return False
        return (
            self._find_named_object(
                context.get("objects", {}) or {},
                kind_key,
                target_ref["name"],
                target_ref["namespace"],
            )
            is not None
        )

    def _relation_score(
        self,
        *,
        pod_workload_ref: dict[str, str] | None,
        hpa_name: str,
        target_ref: dict[str, str],
        namespace_hpa_count: int,
    ) -> int:
        if pod_workload_ref is None:
            return 1 if namespace_hpa_count == 1 else 0

        if (
            target_ref["kind"].lower() == pod_workload_ref["kind"].lower()
            and target_ref["name"] == pod_workload_ref["name"]
        ):
            return 3

        if target_ref["kind"].lower() == pod_workload_ref["kind"].lower() and (
            self._name_related(target_ref["name"], pod_workload_ref["name"])
            or self._name_related(hpa_name, pod_workload_ref["name"])
        ):
            return 2

        if namespace_hpa_count == 1 and self._name_related(
            hpa_name, pod_workload_ref["name"]
        ):
            return 1

        return 0

    def _target_display(self, target_ref: dict[str, str]) -> str:
        kind = target_ref.get("kind") or "<unknown-kind>"
        name = target_ref.get("name") or "<unknown-name>"
        return f"{kind}/{name}"

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        namespace = self._namespace(pod)
        pod_workload_ref = self._pod_workload_ref(pod, context)
        timeline = context.get("timeline")
        timeline_obj = timeline if isinstance(timeline, Timeline) else None

        namespace_hpas = [
            (name, hpa)
            for name, hpa in (context.get("objects", {}).get("hpa", {}) or {}).items()
            if self._namespace(hpa) == namespace
        ]
        if not namespace_hpas:
            return None

        best: dict[str, Any] | None = None
        best_score = (-1, -1, -1)
        for hpa_name, hpa in namespace_hpas:
            target_ref = self._target_ref(hpa, namespace)
            if self._target_exists(context, target_ref):
                continue

            condition = self._failed_get_scale_condition(hpa)
            recent_events = self._recent_failed_get_scale_events(
                timeline_obj,
                hpa_name=hpa_name,
                namespace=namespace,
            )
            if condition is None and not recent_events:
                continue

            relation_score = self._relation_score(
                pod_workload_ref=pod_workload_ref,
                hpa_name=hpa_name,
                target_ref=target_ref,
                namespace_hpa_count=len(namespace_hpas),
            )
            if relation_score <= 0:
                continue

            latest_message = ""
            if recent_events:
                latest_message = self._message(recent_events[-1].get("message"))

            score = (
                relation_score,
                1 if condition is not None else 0,
                len(recent_events),
            )
            if score > best_score:
                best_score = score
                best = {
                    "hpa_name": hpa_name,
                    "namespace": namespace,
                    "pod_workload_ref": pod_workload_ref,
                    "target_ref": target_ref,
                    "condition": condition,
                    "recent_events": recent_events,
                    "latest_message": latest_message,
                }

        return best

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
            raise ValueError("HPAInvalidTargetReference explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        hpa_name = candidate["hpa_name"]
        namespace = candidate["namespace"]
        target_ref = candidate["target_ref"]
        target_display = self._target_display(target_ref)
        condition = candidate.get("condition")
        recent_events = candidate.get("recent_events", [])
        latest_message = candidate.get("latest_message", "")

        chain = CausalChain(
            causes=[
                Cause(
                    code="AUTOSCALER_CONFIGURATION_PRESENT",
                    message=f"HPA '{hpa_name}' is configured to scale {target_display}",
                    role="controller_context",
                ),
                Cause(
                    code="HPA_INVALID_TARGET_REFERENCE",
                    message="HorizontalPodAutoscaler cannot fetch the scale subresource because its target reference is invalid, missing, or unsupported",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="AUTOSCALER_CANNOT_RECONCILE_TARGET",
                    message="Autoscaling decisions are blocked until scaleTargetRef points at a live scalable workload",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"HPA '{hpa_name}' scaleTargetRef points to {target_display}",
            f"Referenced target {target_display} is not present in the current object graph",
        ]
        object_evidence = {
            f"hpa:{hpa_name}": [
                f"scaleTargetRef={target_display}",
                f"Referenced target {target_display} not found",
            ]
        }

        if condition is not None:
            evidence.append(
                f"HPA condition {condition['type']}=False reason={condition['reason']}"
            )
            object_evidence[f"hpa:{hpa_name}"].append(
                f"{condition['type']}=False reason={condition['reason']}"
            )
            object_evidence[f"hpa:{hpa_name}"].append(condition["message"])

        if recent_events:
            evidence.append(
                "Recent horizontal-pod-autoscaler FailedGetScale warnings repeated "
                f"{len(recent_events)} times in the last {self.WINDOW_MINUTES} minutes"
            )
            for event in recent_events:
                event_message = self._message(event.get("message"))
                if (
                    event_message
                    and event_message not in object_evidence[f"hpa:{hpa_name}"]
                ):
                    object_evidence[f"hpa:{hpa_name}"].append(event_message)
            if latest_message:
                evidence.append(
                    f"Latest HPA target resolution warning: {latest_message}"
                )

        pod_workload_ref = candidate.get("pod_workload_ref")
        if pod_workload_ref is not None:
            pod_workload_display = (
                f"{pod_workload_ref['kind']}/{pod_workload_ref['name']}"
            )
            evidence.append(
                f"Analyzed pod belongs to {pod_workload_display}, the most likely workload associated with HPA '{hpa_name}'"
            )
            object_evidence[f"pod:{pod_name}"] = [
                f"Pod belongs to workload {pod_workload_display} in namespace {namespace}"
            ]

        confidence = 0.89
        if condition is not None and recent_events:
            confidence = 0.95
        elif condition is not None:
            confidence = 0.93
        elif len(recent_events) >= 2:
            confidence = 0.91

        ns_flag = f" -n {namespace}" if namespace else ""
        target_kind = target_ref.get("kind") or "<kind>"
        target_name = target_ref.get("name") or "<name>"

        return {
            "root_cause": f"HPA '{hpa_name}' cannot scale because scaleTargetRef {target_display} is invalid or missing",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The workload named in scaleTargetRef was renamed, deleted, or never created",
                "The HPA manifest drifted and still points to an old Deployment, ReplicaSet, or StatefulSet name",
                "scaleTargetRef uses a kind or API resource that does not expose the scale subresource",
                "GitOps or templating changes updated the workload name but did not update the HPA target reference",
            ],
            "suggested_checks": [
                f"kubectl describe hpa {hpa_name}{ns_flag}",
                f"kubectl get hpa {hpa_name}{ns_flag} -o yaml",
                f"kubectl get {target_kind.lower()} {target_name}{ns_flag}",
                "Verify scaleTargetRef.apiVersion, kind, and name match a live scalable workload that supports /scale",
            ],
        }
