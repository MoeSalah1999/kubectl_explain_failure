from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.temporal.base.controllers.replica_oscillation import (
    ReplicaOscillationRule,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class AutoscalingOscillationRule(FailureRule):
    """
    Detect repeated HPA scale reversals before the workload settles.

    Real-world behavior:
    - HPA reacts on a regular sync loop, so noisy or fast-changing utilization
      can produce a recent sequence like scale up -> metrics cool down -> scale
      down -> traffic spikes again
    - the strongest temporal signal is alternating SuccessfulRescale events for
      the same HPA target over one short incident window
    - this rule stays more general than compound HPA thrash/manual-conflict
      diagnoses and can fire earlier while the incident is still forming
    """

    name = "AutoscalingOscillation"
    category = "Temporal"
    priority = 72
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["hpa", "deployment"],
        "context": ["timeline"],
        "optional_objects": ["replicaset"],
    }
    blocks = [
        "ReplicaOscillation",
        "DeploymentReplicaMismatch",
    ]

    WINDOW_MINUTES = 30
    MIN_RESCALE_EVENTS = 3
    MIN_DIRECTION_CHANGES = 2
    MIN_DURATION_SECONDS = 300
    CACHE_KEY = "_autoscaling_oscillation_candidate"
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    RESCALE_SIZE_RE = re.compile(r"new size:\s*(\d+)", re.IGNORECASE)
    RESCALE_REASON_RE = re.compile(r"reason:\s*(.+)$", re.IGNORECASE)
    ABOVE_TARGET_MARKERS = (
        "above target",
        "above the target",
        "too high",
        "higher than target",
        "utilization above",
    )
    BELOW_TARGET_MARKERS = (
        "below target",
        "below the target",
        "all metrics below target",
        "too low",
        "lower than target",
    )

    def __init__(self) -> None:
        self._replica_oscillation_rule = ReplicaOscillationRule()

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _is_false(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value is False
        return str(value or "").strip().lower() == "false"

    def _hpa_failure_condition(self, hpa: dict[str, Any]) -> dict[str, Any] | None:
        for condition in hpa.get("status", {}).get("conditions", []) or []:
            if self._is_false(condition.get("status")) and str(
                condition.get("type", "")
            ) in {"AbleToScale", "ScalingActive"}:
                return condition
        return None

    def _reason_bucket(self, text: str) -> str | None:
        lowered = text.lower()
        if any(marker in lowered for marker in self.ABOVE_TARGET_MARKERS):
            return "high"
        if any(marker in lowered for marker in self.BELOW_TARGET_MARKERS):
            return "low"
        return None

    def _rescale_actions(
        self,
        timeline: Timeline,
        *,
        hpa_name: str,
        deployment_name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if self._event_reason(event) != "successfulrescale":
                continue

            source = self._source_component(event)
            if source and source not in self.HPA_COMPONENTS:
                continue

            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", ""))
            involved_namespace = str(involved.get("namespace", namespace))
            message = self._message(event.get("message"))
            message_lower = message.lower()

            if involved_namespace != namespace:
                continue
            if involved_name and involved_name != hpa_name:
                continue
            if (
                hpa_name.lower() not in message_lower
                and deployment_name.lower() not in message_lower
            ):
                if involved_name != hpa_name:
                    continue

            size_match = self.RESCALE_SIZE_RE.search(message)
            if not size_match:
                continue
            reason_match = self.RESCALE_REASON_RE.search(message)
            reason_text = self._message(reason_match.group(1)) if reason_match else ""

            actions.append(
                {
                    "size": self._as_int(size_match.group(1), 0),
                    "timestamp": self._event_ts(event),
                    "message": message,
                    "reason": reason_text,
                    "bucket": self._reason_bucket(reason_text or message),
                }
            )

        actions.sort(
            key=lambda item: item.get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return actions

    def _scale_pattern(
        self,
        actions: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if len(actions) < self.MIN_RESCALE_EVENTS:
            return None

        sizes: list[int] = []
        buckets: list[str] = []
        deduped: list[dict[str, Any]] = []
        for action in actions:
            if sizes and sizes[-1] == action["size"]:
                continue
            sizes.append(action["size"])
            deduped.append(action)
            bucket = action.get("bucket")
            if bucket:
                buckets.append(bucket)

        if len(sizes) < self.MIN_RESCALE_EVENTS:
            return None

        directions: list[str] = []
        for idx in range(1, len(sizes)):
            if sizes[idx] > sizes[idx - 1]:
                directions.append("up")
            elif sizes[idx] < sizes[idx - 1]:
                directions.append("down")

        if len(directions) < self.MIN_DIRECTION_CHANGES:
            return None
        if any(
            directions[idx] == directions[idx - 1] for idx in range(1, len(directions))
        ):
            return None

        timestamps = [
            action["timestamp"]
            for action in deduped
            if isinstance(action.get("timestamp"), datetime)
        ]
        if len(timestamps) < 2:
            return None
        duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        if duration_seconds < self.MIN_DURATION_SECONDS:
            return None

        return {
            "sizes": sizes,
            "directions": directions,
            "direction_changes": len(directions),
            "duration_seconds": duration_seconds,
            "reason_buckets": list(
                dict.fromkeys(bucket for bucket in buckets if bucket)
            ),
            "deduped": deduped,
        }

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        objects = context.get("objects", {}) or {}
        deployments = objects.get("deployment", {}) or {}
        replicasets = objects.get("replicaset", {}) or {}

        deployment_entry = self._replica_oscillation_rule._candidate_deployment(
            pod,
            deployments,
            replicasets,
        )
        if deployment_entry is None:
            return None

        deployment_name, deployment = deployment_entry
        namespace = self._namespace(deployment)

        hpa_candidate = self._replica_oscillation_rule._candidate_hpa(
            context,
            deployment_name=deployment_name,
            namespace=namespace,
        )
        if hpa_candidate is None:
            return None
        hpa_name, hpa = hpa_candidate

        if self._hpa_failure_condition(hpa) is not None:
            return None

        actions = self._rescale_actions(
            timeline,
            hpa_name=hpa_name,
            deployment_name=deployment_name,
            namespace=namespace,
        )
        pattern = self._scale_pattern(actions)
        if pattern is None:
            return None

        deployment_symptom = self._replica_oscillation_rule._deployment_symptom(
            deployment_name,
            deployment,
        )
        if deployment_symptom is None:
            return None

        rs_evidence: dict[str, Any] | None = None
        if replicasets:
            workload_rs = self._replica_oscillation_rule._owned_replicasets(
                deployment_name,
                namespace,
                replicasets,
            )
            if workload_rs:
                scale_actions = self._replica_oscillation_rule._scale_actions(
                    timeline,
                    deployment_name=deployment_name,
                    replicaset_names=set(workload_rs),
                )
                best_score = (-1, -1.0)
                for rs_name, rs in workload_rs.items():
                    rs_actions = [
                        action
                        for action in scale_actions
                        if action["rs_name"] == rs_name
                    ]
                    rs_pattern = self._replica_oscillation_rule._pattern_details(
                        rs_actions
                    )
                    if rs_pattern is None:
                        continue
                    score = (
                        len(rs_pattern["collapsed"]),
                        rs_pattern["duration_seconds"],
                    )
                    if score > best_score:
                        best_score = score
                        rs_evidence = {
                            "rs_name": rs_name,
                            "rs": rs,
                            "pattern": rs_pattern,
                        }

        return {
            "deployment_name": deployment_name,
            "deployment": deployment,
            "namespace": namespace,
            "hpa_name": hpa_name,
            "hpa": hpa,
            "pattern": pattern,
            "actions": actions,
            "deployment_symptom": deployment_symptom,
            "rs_evidence": rs_evidence,
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
            raise ValueError("AutoscalingOscillation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        hpa_name = candidate["hpa_name"]
        deployment_name = candidate["deployment_name"]
        pattern = candidate["pattern"]
        deployment_symptom = candidate["deployment_symptom"]
        minutes = pattern["duration_seconds"] / 60.0

        chain = CausalChain(
            causes=[
                Cause(
                    code="AUTOSCALER_TARGET_IDENTIFIED",
                    message=f"HPA '{hpa_name}' is managing Deployment/{deployment_name}",
                    role="controller_context",
                ),
                Cause(
                    code="AUTOSCALING_OSCILLATION",
                    message="Autoscaler replica decisions are oscillating between scale-up and scale-down instead of stabilizing",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="METRIC_SIGNAL_REVERSALS",
                    message="Recent autoscaling decisions repeatedly flipped between high-pressure and low-pressure metric signals",
                    role="controller_intermediate",
                ),
                Cause(
                    code="WORKLOAD_NOT_YET_STABLE",
                    message=(
                        f"Deployment remains below stable capacity at "
                        f"{deployment_symptom['available']}/{deployment_symptom['desired']} "
                        "available replicas while autoscaling keeps changing target size"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"HPA '{hpa_name}' rescaled Deployment/{deployment_name} as: {' -> '.join(str(size) for size in pattern['sizes'])}",
            f"Autoscaling direction reversed {pattern['direction_changes']} times over {minutes:.1f} minutes",
            deployment_symptom["message"],
        ]

        if {"high", "low"}.issubset(set(pattern["reason_buckets"])):
            evidence.append(
                "SuccessfulRescale reasons alternated between above-target and below-target metric signals"
            )
        elif pattern["reason_buckets"]:
            evidence.append(
                "SuccessfulRescale reasons changed repeatedly during the same autoscaling incident"
            )

        rs_evidence = candidate.get("rs_evidence")
        if rs_evidence is not None:
            evidence.append(
                f"ReplicaSet '{rs_evidence['rs_name']}' applied those reversals as: {' -> '.join(rs_evidence['pattern']['display'])}"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                f"Pod belongs to autoscaled workload Deployment/{deployment_name}"
            ],
            f"hpa:{hpa_name}": [
                f"scaleTargetRef=Deployment/{deployment_name}",
                f"SuccessfulRescale sizes alternated as {' -> '.join(str(size) for size in pattern['sizes'])}",
            ],
            f"deployment:{deployment_name}": [
                f"updatedReplicas={deployment_symptom['updated']}, availableReplicas={deployment_symptom['available']}, desiredReplicas={deployment_symptom['desired']}"
            ],
        }

        hpa_status = candidate["hpa"].get("status", {}) or {}
        current_replicas = self._as_int(hpa_status.get("currentReplicas"), -1)
        desired_replicas = self._as_int(hpa_status.get("desiredReplicas"), -1)
        if current_replicas >= 0 and desired_replicas >= 0:
            object_evidence[f"hpa:{hpa_name}"].append(
                f"currentReplicas={current_replicas}, desiredReplicas={desired_replicas}"
            )

        if rs_evidence is not None:
            object_evidence[f"replicaset:{rs_evidence['rs_name']}"] = [
                f"scaleUpEvents={rs_evidence['pattern']['up_count']}, scaleDownEvents={rs_evidence['pattern']['down_count']}",
                f"targetReplicaSizes={','.join(str(size) for size in rs_evidence['pattern']['unique_sizes'])}",
            ]

        return {
            "root_cause": f"HPA '{hpa_name}' is oscillating between scale-up and scale-down decisions for Deployment/{deployment_name}",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "CPU or custom metric values are hovering near the HPA target and repeatedly crossing it in opposite directions",
                "Pods need longer to become Ready than the autoscaler needs to make its next scaling decision",
                "Scale-down stabilization or scaling policy tuning is too weak for this workload's traffic pattern",
                "Burst traffic and fast cooldown periods are causing the HPA control loop to over-correct in both directions",
            ],
            "suggested_checks": [
                f"kubectl describe hpa {hpa_name} -n {candidate['namespace']}",
                f"kubectl get hpa {hpa_name} -n {candidate['namespace']} -o yaml",
                "Inspect recent metric history around the HPA target threshold instead of only current utilization",
                "Review HPA behavior, stabilization windows, and readiness timing for over-correction",
            ],
        }
