from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class VerticalPodAutoscalerRecommendationFailureRule(FailureRule):
    """
    Detects a VPA that is not producing resource recommendations for the
    workload associated with the analyzed pod.

    Real-world behavior:
    - VPA reports recommendation readiness via RecommendationProvided plus
      supporting conditions such as FetchingHistory / NoPodsMatched
    - brief FetchingHistory periods are normal, so this rule requires the
      recommendation gap to persist and be corroborated by recent recommender
      signals before matching
    """

    name = "VerticalPodAutoscalerRecommendationFailure"
    category = "Controller"
    priority = 52
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["vpa"],
        "context": ["timeline"],
        "optional_objects": ["deployment", "replicaset", "statefulset", "daemonset"],
    }

    WINDOW_MINUTES = 45
    FETCHING_HISTORY_GRACE_MINUTES = 30
    NO_PODS_MATCHED_GRACE_MINUTES = 10
    CACHE_KEY = "_vpa_recommendation_failure_candidate"
    VPA_COMPONENTS = {"vpa-recommender", "recommender", "vertical-pod-autoscaler"}
    EVENT_REASON_MARKERS = {
        "recommendationprovided",
        "fetchinghistory",
        "nopodsmatched",
        "lowconfidence",
    }
    EVENT_MESSAGE_MARKERS = (
        "cannot compute recommendation",
        "no recommendation",
        "fetching history",
        "no pods match this vpa object",
        "insufficient history",
        "not enough samples",
        "low confidence",
    )
    TARGET_KIND_TO_OBJECT_KEY = {
        "deployment": "deployment",
        "replicaset": "replicaset",
        "statefulset": "statefulset",
        "daemonset": "daemonset",
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

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _reason(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _is_true(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is True
        return str(value).strip().lower() == "true"

    def _is_false(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"

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

        daemonset_name = self._owner_ref(pod, "DaemonSet")
        if daemonset_name:
            return {"kind": "DaemonSet", "name": daemonset_name, "namespace": namespace}

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
            return {"kind": "ReplicaSet", "name": rs_name, "namespace": namespace}

        return None

    def _normalize_name(self, value: str) -> str:
        return (
            value.lower()
            .replace("-vpa", "")
            .replace("vpa-", "")
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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _target_ref(self, vpa: dict[str, Any], namespace: str) -> dict[str, str]:
        target = vpa.get("spec", {}).get("targetRef", {}) or {}
        return {
            "apiVersion": str(target.get("apiVersion", "")),
            "kind": str(target.get("kind", "")),
            "name": str(target.get("name", "")),
            "namespace": namespace,
        }

    def _target_exists(
        self, context: dict[str, Any], target_ref: dict[str, str]
    ) -> bool:
        kind_key = self.TARGET_KIND_TO_OBJECT_KEY.get(target_ref["kind"].lower())
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

    def _target_display(self, target_ref: dict[str, str]) -> str:
        return f"{target_ref.get('kind') or '<unknown-kind>'}/{target_ref.get('name') or '<unknown-name>'}"

    def _relation_score(
        self,
        *,
        pod_workload_ref: dict[str, str] | None,
        vpa_name: str,
        target_ref: dict[str, str],
        namespace_vpa_count: int,
    ) -> int:
        if pod_workload_ref is None:
            return 1 if namespace_vpa_count == 1 else 0
        if (
            target_ref["kind"].lower() == pod_workload_ref["kind"].lower()
            and target_ref["name"] == pod_workload_ref["name"]
        ):
            return 3
        if target_ref["kind"].lower() == pod_workload_ref["kind"].lower() and (
            self._name_related(target_ref["name"], pod_workload_ref["name"])
            or self._name_related(vpa_name, pod_workload_ref["name"])
        ):
            return 2
        if namespace_vpa_count == 1 and self._name_related(
            vpa_name, pod_workload_ref["name"]
        ):
            return 1
        return 0

    def _conditions_by_type(self, vpa: dict[str, Any]) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        for condition in vpa.get("status", {}).get("conditions", []) or []:
            cond_type = str(condition.get("type", "")).strip().lower()
            if cond_type:
                results[cond_type] = condition
        return results

    def _recommendation_missing(self, vpa: dict[str, Any]) -> bool:
        recommendation = vpa.get("status", {}).get("recommendation", {}) or {}
        return not bool(recommendation.get("containerRecommendations"))

    def _condition_age_minutes(
        self,
        condition: dict[str, Any] | None,
        *,
        reference_time: datetime | None,
    ) -> float:
        if condition is None or reference_time is None:
            return 0.0
        transitioned = self._parse_ts(condition.get("lastTransitionTime"))
        if transitioned is None:
            return 0.0
        return max(0.0, (reference_time - transitioned).total_seconds() / 60.0)

    def _recent_recommendation_events(
        self,
        timeline: Timeline,
        *,
        vpa_name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            source = self._source_component(event)
            if source and source not in self.VPA_COMPONENTS:
                continue

            involved = event.get("involvedObject", {}) or {}
            if isinstance(involved, dict) and involved:
                involved_kind = str(involved.get("kind", "")).lower()
                involved_name = str(involved.get("name", ""))
                involved_namespace = str(involved.get("namespace", namespace))
                if involved_namespace != namespace:
                    continue
                if involved_kind and involved_kind != "verticalpodautoscaler":
                    continue
                if involved_name and involved_name != vpa_name:
                    continue

            reason = self._reason(event.get("reason"))
            message = self._message(event.get("message")).lower()
            if reason in self.EVENT_REASON_MARKERS or any(
                marker in message for marker in self.EVENT_MESSAGE_MARKERS
            ):
                results.append(event)

        results.sort(
            key=lambda event: self._event_ts(event)
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return results

    def _reference_time(
        self, timeline: Timeline, recent_events: list[dict[str, Any]]
    ) -> datetime | None:
        latest: datetime | None = None
        for event in recent_events:
            ts = self._event_ts(event)
            if ts is not None and (latest is None or ts > latest):
                latest = ts
        if latest is not None:
            return latest
        for event in reversed(timeline.events):
            ts = self._event_ts(event)
            if ts is not None:
                return ts
        return None

    def _workload_symptom(
        self,
        context: dict[str, Any],
        workload_ref: dict[str, str] | None,
    ) -> str | None:
        if workload_ref is None:
            return None
        objects = context.get("objects", {}) or {}
        workload = self._find_named_object(
            objects,
            workload_ref["kind"].lower(),
            workload_ref["name"],
            workload_ref["namespace"],
        )
        if workload is None:
            return None

        status = workload.get("status", {}) or {}
        spec = workload.get("spec", {}) or {}
        if workload_ref["kind"] == "Deployment":
            desired = int(status.get("replicas", spec.get("replicas", 0)) or 0)
            available = int(
                status.get("availableReplicas", status.get("readyReplicas", 0)) or 0
            )
            if desired > 0 and available < desired:
                return (
                    f"Deployment '{workload_ref['name']}' currently has "
                    f"{available}/{desired} available replicas while VPA is not producing recommendations"
                )
        if workload_ref["kind"] == "StatefulSet":
            desired = int(spec.get("replicas", 0) or 0)
            ready = int(status.get("readyReplicas", 0) or 0)
            if desired > 0 and ready < desired:
                return (
                    f"StatefulSet '{workload_ref['name']}' currently has "
                    f"{ready}/{desired} ready replicas while VPA is not producing recommendations"
                )
        if workload_ref["kind"] == "DaemonSet":
            desired = int(status.get("desiredNumberScheduled", 0) or 0)
            available = int(status.get("numberAvailable", 0) or 0)
            if desired > 0 and available < desired:
                return (
                    f"DaemonSet '{workload_ref['name']}' currently has "
                    f"{available}/{desired} available nodes while VPA is not producing recommendations"
                )
        return None

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        namespace = self._namespace(pod)
        pod_workload_ref = self._pod_workload_ref(pod, context)
        namespace_vpas = [
            (name, vpa)
            for name, vpa in (context.get("objects", {}).get("vpa", {}) or {}).items()
            if self._namespace(vpa) == namespace
        ]
        if not namespace_vpas:
            return None

        best: dict[str, Any] | None = None
        best_score = (-1, -1, -1, -1.0)
        for vpa_name, vpa in namespace_vpas:
            target_ref = self._target_ref(vpa, namespace)
            if not self._target_exists(context, target_ref):
                continue

            relation_score = self._relation_score(
                pod_workload_ref=pod_workload_ref,
                vpa_name=vpa_name,
                target_ref=target_ref,
                namespace_vpa_count=len(namespace_vpas),
            )
            if relation_score <= 0 or not self._recommendation_missing(vpa):
                continue

            conditions = self._conditions_by_type(vpa)
            recommendation_provided = conditions.get("recommendationprovided")
            fetching_history = conditions.get("fetchinghistory")
            no_pods_matched = conditions.get("nopodsmatched")
            low_confidence = conditions.get("lowconfidence")

            recent_events = self._recent_recommendation_events(
                timeline,
                vpa_name=vpa_name,
                namespace=namespace,
            )
            reference_time = self._reference_time(timeline, recent_events)
            fetching_age = self._condition_age_minutes(
                fetching_history, reference_time=reference_time
            )
            no_pods_age = self._condition_age_minutes(
                no_pods_matched, reference_time=reference_time
            )

            recommendation_missing_state = (
                recommendation_provided is not None
                and self._is_false(recommendation_provided.get("status"))
            )
            sustained_fetching_history = (
                fetching_history is not None
                and self._is_true(fetching_history.get("status"))
                and (
                    fetching_age >= self.FETCHING_HISTORY_GRACE_MINUTES
                    or len(recent_events) >= 3
                )
            )
            sustained_no_pods_matched = (
                no_pods_matched is not None
                and self._is_true(no_pods_matched.get("status"))
                and (
                    no_pods_age >= self.NO_PODS_MATCHED_GRACE_MINUTES
                    or len(recent_events) >= 2
                )
            )
            low_confidence_without_recommendation = (
                low_confidence is not None
                and self._is_true(low_confidence.get("status"))
                and recommendation_missing_state
                and len(recent_events) >= 3
            )

            if not (
                recommendation_missing_state
                and (
                    sustained_fetching_history
                    or sustained_no_pods_matched
                    or low_confidence_without_recommendation
                    or len(recent_events) >= 4
                )
            ):
                continue

            primary_condition = (
                fetching_history
                if sustained_fetching_history
                else no_pods_matched if sustained_no_pods_matched else low_confidence
            )
            primary_age = max(fetching_age, no_pods_age)
            workload_symptom = self._workload_symptom(context, pod_workload_ref)
            latest_message = (
                self._message(recent_events[-1].get("message")) if recent_events else ""
            )

            score = (
                relation_score,
                len(recent_events),
                1 if primary_condition is not None else 0,
                primary_age,
            )
            if score > best_score:
                best_score = score
                best = {
                    "vpa_name": vpa_name,
                    "namespace": namespace,
                    "target_ref": target_ref,
                    "pod_workload_ref": pod_workload_ref,
                    "conditions": conditions,
                    "recent_events": recent_events,
                    "primary_condition": primary_condition,
                    "primary_age": primary_age,
                    "latest_message": latest_message,
                    "workload_symptom": workload_symptom,
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
            raise ValueError(
                "VerticalPodAutoscalerRecommendationFailure explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = candidate["namespace"]
        vpa_name = candidate["vpa_name"]
        target_ref = candidate["target_ref"]
        target_display = self._target_display(target_ref)
        conditions = candidate["conditions"]
        recent_events = candidate["recent_events"]
        primary_condition = candidate.get("primary_condition")
        latest_message = candidate.get("latest_message", "")
        workload_symptom = candidate.get("workload_symptom")

        evidence = [
            f"VPA '{vpa_name}' targets {target_display}",
            f"VPA '{vpa_name}' has no current recommendation in status.recommendation.containerRecommendations",
        ]
        object_evidence = {
            f"vpa:{vpa_name}": [
                f"targetRef={target_display}",
                "status.recommendation.containerRecommendations is empty",
            ]
        }

        recommendation_provided = conditions.get("recommendationprovided")
        if recommendation_provided is not None:
            evidence.append(
                "VPA condition RecommendationProvided="
                f"{recommendation_provided.get('status')} reason="
                f"{recommendation_provided.get('reason', '<unknown>')}"
            )
            object_evidence[f"vpa:{vpa_name}"].append(
                "RecommendationProvided="
                f"{recommendation_provided.get('status')} reason="
                f"{recommendation_provided.get('reason', '<unknown>')}"
            )
            if recommendation_provided.get("message"):
                object_evidence[f"vpa:{vpa_name}"].append(
                    str(recommendation_provided["message"])
                )

        if primary_condition is not None:
            cond_type = str(primary_condition.get("type", "<unknown>"))
            evidence.append(
                f"VPA condition {cond_type}=True persisted for about {candidate['primary_age']:.0f} minutes"
            )
            object_evidence[f"vpa:{vpa_name}"].append(
                f"{cond_type}=True reason={primary_condition.get('reason', '<unknown>')}"
            )
            if primary_condition.get("message"):
                object_evidence[f"vpa:{vpa_name}"].append(
                    str(primary_condition["message"])
                )

        if recent_events:
            evidence.append(
                "Recent vpa-recommender recommendation-gap signals repeated "
                f"{len(recent_events)} times in the last {self.WINDOW_MINUTES} minutes"
            )
            for event in recent_events:
                event_message = self._message(event.get("message"))
                if (
                    event_message
                    and event_message not in object_evidence[f"vpa:{vpa_name}"]
                ):
                    object_evidence[f"vpa:{vpa_name}"].append(event_message)
            if latest_message:
                evidence.append(f"Latest VPA recommender warning: {latest_message}")

        pod_workload_ref = candidate.get("pod_workload_ref")
        if pod_workload_ref is not None:
            workload_display = f"{pod_workload_ref['kind']}/{pod_workload_ref['name']}"
            object_evidence[f"pod:{pod_name}"] = [
                f"Pod belongs to workload {workload_display} associated with VPA '{vpa_name}'"
            ]

        if workload_symptom:
            evidence.append(workload_symptom)
            if pod_workload_ref is not None:
                object_evidence[
                    f"{pod_workload_ref['kind'].lower()}:{pod_workload_ref['name']}"
                ] = [workload_symptom]

        confidence = 0.92
        if primary_condition is not None and len(recent_events) >= 3:
            confidence = 0.96
        elif primary_condition is not None:
            confidence = 0.94
        elif len(recent_events) >= 4:
            confidence = 0.93

        chain = CausalChain(
            causes=[
                Cause(
                    code="VPA_TARGET_IDENTIFIED",
                    message=f"VerticalPodAutoscaler '{vpa_name}' is configured for {target_display}",
                    role="controller_context",
                ),
                Cause(
                    code="VPA_RECOMMENDATION_FAILURE",
                    message="Vertical Pod Autoscaler is not producing a usable resource recommendation for the workload",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="VPA_RIGHT_SIZING_STALLED",
                    message="Automated vertical resource recommendation is stalled until the recommender has enough valid pod history and target matching data",
                    role="workload_symptom",
                ),
            ]
        )

        ns_flag = f" -n {namespace}" if namespace else ""
        return {
            "root_cause": f"VPA '{vpa_name}' is failing to produce resource recommendations for {target_display}",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The VPA recommender still has insufficient history for the target pods well beyond the normal warm-up window",
                "Target pods are churning or being recreated too often for the recommender to build stable usage history",
                "The VPA target matches no live pods, or pod labels/selectors no longer align with the controller referenced by targetRef",
                "Recommender-side history or checkpoint collection is degraded, leaving RecommendationProvided=False",
            ],
            "suggested_checks": [
                f"kubectl describe vpa {vpa_name}{ns_flag}",
                f"kubectl get vpa {vpa_name}{ns_flag} -o yaml",
                "Inspect vpa-recommender logs for history/checkpoint or pod-matching errors",
                f"Verify that {target_display} currently owns stable pods long enough for VPA history collection",
            ],
        }
