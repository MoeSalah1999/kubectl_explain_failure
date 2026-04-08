from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class HPAMetricsUnavailableRule(FailureRule):
    """
    Detects a HorizontalPodAutoscaler that cannot calculate desired replicas
    because the metrics pipeline is unavailable or invalid for this workload.

    Real-world behavior:
    - HPA commonly surfaces this as ScalingActive=False with reasons such as
      FailedGetResourceMetric / FailedGetPodsMetric / FailedGetExternalMetric
    - the same incident usually produces repeated recent Warning events from
      horizontal-pod-autoscaler against the HPA object
    - this blocks autoscaling-driven recovery for the workload even when the
      target controller itself remains present
    """

    name = "HPAMetricsUnavailable"
    category = "Controller"
    priority = 54
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["hpa"],
        "optional_objects": ["deployment", "replicaset", "statefulset"],
    }

    WINDOW_MINUTES = 20
    CACHE_KEY = "_hpa_metrics_unavailable_candidate"
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    METRICS_FAILURE_REASONS = {
        "failedgetresourcemetric",
        "failedgetpodsmetric",
        "failedgetobjectmetric",
        "failedgetexternalmetric",
        "failedgetcontainerresourcemetric",
        "failedcomputemetricsreplicas",
    }
    METRICS_MESSAGE_MARKERS = (
        "unable to compute the replica count",
        "unable to get metrics",
        "unable to fetch metrics",
        "no metrics returned from resource metrics api",
        "unable to fetch metrics from resource metrics api",
        "unable to fetch metrics from custom metrics api",
        "unable to fetch metrics from external metrics api",
        "missing request for",
        "did not receive metrics",
        "failed to get cpu utilization",
        "failed to get memory utilization",
        "metrics api",
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
            self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

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
        if isinstance(direct, dict):
            if self._namespace(direct) == namespace:
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
        self, pod: dict[str, Any], context: dict[str, Any]
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

    def _reason(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _condition_is_false(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"

    def _looks_metrics_failure(self, *, reason: str, message: str) -> bool:
        reason_norm = self._reason(reason)
        message_norm = message.lower()

        if reason_norm in self.METRICS_FAILURE_REASONS:
            return True

        return any(marker in message_norm for marker in self.METRICS_MESSAGE_MARKERS)

    def _metrics_failure_condition(self, hpa: dict[str, Any]) -> dict[str, str] | None:
        for condition in hpa.get("status", {}).get("conditions", []) or []:
            cond_type = str(condition.get("type", ""))
            reason = self._message(condition.get("reason"))
            message = self._message(condition.get("message"))
            if cond_type != "ScalingActive":
                continue
            if not self._condition_is_false(condition.get("status")):
                continue
            if not self._looks_metrics_failure(reason=reason, message=message):
                continue
            return {
                "type": cond_type,
                "reason": reason or "<unknown>",
                "message": message or "HPA reports metrics are unavailable",
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

    def _relevant_events(
        self,
        timeline: Timeline | None,
        *,
        hpa_name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        if timeline is None:
            return []

        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        results: list[dict[str, Any]] = []
        for event in recent:
            source = self._source_component(event)
            if source and source not in self.HPA_COMPONENTS:
                continue
            if not self._event_targets_hpa(
                event, hpa_name=hpa_name, namespace=namespace
            ):
                continue

            reason = self._message(event.get("reason"))
            message = self._message(event.get("message"))
            if not self._looks_metrics_failure(reason=reason, message=message):
                continue
            results.append(event)

        results.sort(
            key=lambda event: self._event_ts(event)
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return results

    def _replica_counts(self, workload: dict[str, Any], kind: str) -> tuple[int, int]:
        status = workload.get("status", {}) or {}
        spec = workload.get("spec", {}) or {}

        if kind == "Deployment":
            desired = int(status.get("replicas", spec.get("replicas", 0)) or 0)
            available = int(
                status.get("availableReplicas", status.get("readyReplicas", 0)) or 0
            )
            return desired, available

        if kind == "StatefulSet":
            desired = int(spec.get("replicas", 0) or 0)
            available = int(status.get("readyReplicas", 0) or 0)
            return desired, available

        desired = int(status.get("replicas", spec.get("replicas", 0)) or 0)
        available = int(
            status.get("availableReplicas", status.get("readyReplicas", 0)) or 0
        )
        return desired, available

    def _workload_symptom(
        self,
        context: dict[str, Any],
        workload_ref: dict[str, str] | None,
    ) -> str | None:
        if workload_ref is None:
            return None

        objects = context.get("objects", {}) or {}
        kind_key = workload_ref["kind"].lower()
        workload = self._find_named_object(
            objects,
            kind_key,
            workload_ref["name"],
            workload_ref["namespace"],
        )
        if workload is None:
            return None

        desired, available = self._replica_counts(workload, workload_ref["kind"])
        if desired > 0 and available < desired:
            return (
                f"{workload_ref['kind']} '{workload_ref['name']}' currently has "
                f"{available}/{desired} available replicas while autoscaling is degraded"
            )

        return None

    def _matching_hpas(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[tuple[str, dict[str, Any], dict[str, str] | None]]:
        namespace = self._namespace(pod)
        workload_ref = self._pod_workload_ref(pod, context)
        hpa_objs = context.get("objects", {}).get("hpa", {}) or {}

        matches: list[tuple[str, dict[str, Any], dict[str, str] | None]] = []
        in_namespace: list[tuple[str, dict[str, Any]]] = [
            (name, hpa)
            for name, hpa in hpa_objs.items()
            if self._namespace(hpa) == namespace
        ]

        for hpa_name, hpa in in_namespace:
            target = hpa.get("spec", {}).get("scaleTargetRef", {}) or {}
            target_kind = str(target.get("kind", ""))
            target_name = str(target.get("name", ""))

            if workload_ref is not None:
                if (
                    target_kind.lower() == workload_ref["kind"].lower()
                    and target_name == workload_ref["name"]
                ):
                    matches.append((hpa_name, hpa, workload_ref))
                continue

            if len(in_namespace) == 1:
                fallback_ref = None
                if target_kind and target_name:
                    fallback_ref = {
                        "kind": target_kind,
                        "name": target_name,
                        "namespace": namespace,
                    }
                matches.append((hpa_name, hpa, fallback_ref))

        return matches

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        timeline_obj = timeline if isinstance(timeline, Timeline) else None
        namespace = self._namespace(pod)

        best: dict[str, Any] | None = None
        best_score = (-1, -1, -1)
        for hpa_name, hpa, workload_ref in self._matching_hpas(pod, context):
            condition = self._metrics_failure_condition(hpa)
            recent_events = self._relevant_events(
                timeline_obj,
                hpa_name=hpa_name,
                namespace=namespace,
            )

            if condition is None and len(recent_events) < 2:
                continue

            workload_desc = "<unknown target>"
            if workload_ref is not None:
                workload_desc = f"{workload_ref['kind']}/{workload_ref['name']}"

            symptom = self._workload_symptom(context, workload_ref)
            latest_event = recent_events[-1] if recent_events else None
            latest_message = (
                self._message(latest_event.get("message")) if latest_event else ""
            )
            latest_reason = (
                self._message(latest_event.get("reason")) if latest_event else ""
            )
            score = (
                1 if condition is not None else 0,
                len(recent_events),
                1 if symptom else 0,
            )
            if score > best_score:
                best_score = score
                best = {
                    "hpa_name": hpa_name,
                    "namespace": namespace,
                    "workload_ref": workload_ref,
                    "workload_desc": workload_desc,
                    "condition": condition,
                    "recent_events": recent_events,
                    "latest_event_reason": latest_reason or "<unknown>",
                    "latest_event_message": latest_message,
                    "symptom": symptom,
                    "scale_target": hpa.get("spec", {}).get("scaleTargetRef", {}) or {},
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
            raise ValueError("HPAMetricsUnavailable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        hpa_name = candidate["hpa_name"]
        namespace = candidate["namespace"]
        workload_desc = candidate["workload_desc"]
        condition = candidate.get("condition")
        recent_events = candidate.get("recent_events", [])

        evidence = [
            f"HPA '{hpa_name}' targets {workload_desc}",
        ]
        object_evidence = {
            f"hpa:{hpa_name}": [
                f"scaleTargetRef={workload_desc}",
            ],
            f"pod:{pod_name}": [f"Pod belongs to autoscaled workload {workload_desc}"],
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
                "Recent horizontal-pod-autoscaler warnings repeated "
                f"{len(recent_events)} times in the last {self.WINDOW_MINUTES} minutes"
            )
            latest_message = candidate.get("latest_event_message")
            if latest_message:
                evidence.append(f"Latest HPA metrics warning: {latest_message}")
                object_evidence[f"hpa:{hpa_name}"].append(latest_message)

        if candidate.get("symptom"):
            evidence.append(candidate["symptom"])
            workload_ref = candidate.get("workload_ref")
            if workload_ref is not None:
                object_evidence[
                    f"{workload_ref['kind'].lower()}:{workload_ref['name']}"
                ] = [candidate["symptom"]]

        confidence = 0.93
        if condition is not None and len(recent_events) >= 2:
            confidence = 0.97
        elif condition is not None and recent_events:
            confidence = 0.96
        elif len(recent_events) >= 3:
            confidence = 0.94

        ns_flag = f" -n {namespace}" if namespace else ""
        chain = CausalChain(
            causes=[
                Cause(
                    code="AUTOSCALER_TARGET_IDENTIFIED",
                    message=f"HPA '{hpa_name}' manages {workload_desc}",
                    role="controller_context",
                ),
                Cause(
                    code="HPA_METRICS_UNAVAILABLE",
                    message="HorizontalPodAutoscaler cannot calculate desired replicas because required metrics are unavailable or invalid",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="AUTOSCALING_RESPONSE_BLOCKED",
                    message="Scale decisions for the workload are stalled until metric collection or adapter access recovers",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": f"HPA '{hpa_name}' cannot compute desired replicas because autoscaling metrics are unavailable",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Metrics Server or a custom/external metrics adapter is unavailable or returning errors",
                "The HPA metric spec no longer matches a serving metric series or selector",
                "One or more autoscaled containers are missing the resource requests required for utilization-based metrics",
                "API aggregation or control-plane connectivity problems are preventing the HPA controller from reading metrics",
            ],
            "suggested_checks": [
                f"kubectl describe hpa {hpa_name}{ns_flag}",
                f"kubectl get hpa {hpa_name}{ns_flag} -o yaml",
                "kubectl get --raw /apis/metrics.k8s.io/v1beta1/  # or inspect the custom/external metrics adapter",
                "Verify every autoscaled container defines the CPU/memory requests required by the HPA metric type",
            ],
        }
