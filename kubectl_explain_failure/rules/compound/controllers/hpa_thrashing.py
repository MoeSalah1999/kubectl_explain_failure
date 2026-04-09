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


class HPAThrashingRule(FailureRule):
    """
    Detect repeated HPA replica recommendation reversals for the same workload.

    Real-world behavior:
    - HPA flapping shows up as alternating SuccessfulRescale events for the same
      workload within one recent incident window
    - the workload controller keeps applying those reversals to the same
      ReplicaSet instead of converging on a stable desired size
    - aggressive HPA behavior such as disabling downscale stabilization can
      make this pattern materially more likely in production
    """

    name = "HPAThrashing"
    category = "Compound"
    priority = 76
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["hpa", "replicaset"],
        "context": ["timeline"],
        "optional_objects": ["deployment"],
    }
    blocks = [
        "AutoscalingOscillation",
        "ReplicaOscillation",
        "DeploymentReplicaMismatch",
        "DeploymentRolloutStalled",
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetUnavailable",
        "ReplicaSetCreateFailure",
    ]

    WINDOW_MINUTES = 30
    MIN_RESCALE_EVENTS = 4
    MIN_DURATION_SECONDS = 300
    CACHE_KEY = "_hpa_thrashing_candidate"
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    RESCALE_SIZE_RE = re.compile(r"new size:\s*(\d+)", re.IGNORECASE)
    RESCALE_REASON_RE = re.compile(r"reason:\s*(.+)$", re.IGNORECASE)

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

    def _target_display(self, hpa: dict[str, Any], candidate: dict[str, Any]) -> str:
        scale_target = hpa.get("spec", {}).get("scaleTargetRef", {}) or {}
        target_kind = str(scale_target.get("kind", "")).strip()
        target_name = str(scale_target.get("name", "")).strip()
        if target_kind and target_name:
            return f"{target_kind}/{target_name}"
        if candidate.get("deployment_name"):
            return f"Deployment/{candidate['deployment_name']}"
        return f"ReplicaSet/{candidate['rs_name']}"

    def _event_targets_hpa(
        self,
        event: dict[str, Any],
        *,
        hpa_name: str,
        deployment_name: str | None,
        namespace: str,
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        if isinstance(involved, dict) and involved:
            involved_namespace = str(involved.get("namespace", namespace))
            involved_kind = str(involved.get("kind", "")).lower()
            involved_name = str(involved.get("name", ""))
            if involved_namespace != namespace:
                return False
            if involved_kind and involved_kind != "horizontalpodautoscaler":
                return False
            if involved_name and involved_name != hpa_name:
                return False
            return True

        message = self._message(event.get("message")).lower()
        if hpa_name.lower() in message:
            return True
        if deployment_name and deployment_name.lower() in message:
            return True
        return False

    def _rescale_actions(
        self,
        timeline: Timeline,
        *,
        hpa_name: str,
        deployment_name: str | None,
        namespace: str,
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if self._event_reason(event) != "successfulrescale":
                continue

            source = self._source_component(event)
            if source and source not in self.HPA_COMPONENTS:
                continue

            if not self._event_targets_hpa(
                event,
                hpa_name=hpa_name,
                deployment_name=deployment_name,
                namespace=namespace,
            ):
                continue

            message = self._message(event.get("message"))
            size_match = self.RESCALE_SIZE_RE.search(message)
            if not size_match:
                continue

            reason_match = self.RESCALE_REASON_RE.search(message)
            actions.append(
                {
                    "size": self._as_int(size_match.group(1), 0),
                    "timestamp": self._event_ts(event),
                    "message": message,
                    "reason": (
                        self._message(reason_match.group(1)) if reason_match else ""
                    ),
                }
            )

        actions.sort(
            key=lambda item: item.get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return actions

    def _behavior_context(self, hpa: dict[str, Any]) -> dict[str, Any]:
        behavior = hpa.get("spec", {}).get("behavior", {}) or {}
        scale_down = behavior.get("scaleDown", {}) or {}

        evidence: list[str] = []
        object_items: list[str] = []
        aggressive = False

        if scale_down:
            window_raw = scale_down.get("stabilizationWindowSeconds")
            if window_raw is not None:
                window = self._as_int(window_raw, -1)
                object_items.append(f"scaleDown.stabilizationWindowSeconds={window}")
                if window == 0:
                    evidence.append(
                        "HPA behavior disables downscale damping with scaleDown.stabilizationWindowSeconds=0"
                    )
                    aggressive = True
                elif 0 < window <= 60:
                    evidence.append(
                        f"HPA behavior uses only {window}s of downscale stabilization"
                    )
                    aggressive = True

            select_policy = str(scale_down.get("selectPolicy", "")).strip()
            if select_policy:
                object_items.append(f"scaleDown.selectPolicy={select_policy}")

            policies = scale_down.get("policies", []) or []
            if isinstance(policies, list) and policies:
                rendered: list[str] = []
                aggressive_policy = False
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                    policy_type = str(policy.get("type", "")).strip() or "<type>"
                    value = self._as_int(policy.get("value"), 0)
                    period = self._as_int(policy.get("periodSeconds"), 0)
                    rendered.append(f"{policy_type}:{value}/{period}s")
                    if (
                        period
                        and period <= 60
                        and (
                            value >= 50
                            or (policy_type.lower() == "pods" and value >= 2)
                        )
                    ):
                        aggressive_policy = True
                if rendered:
                    object_items.append(f"scaleDown.policies={', '.join(rendered)}")
                if aggressive_policy and select_policy.lower() == "max":
                    aggressive = True

        return {
            "evidence": evidence,
            "object_items": object_items,
            "aggressive": aggressive,
        }

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        candidate = self._replica_oscillation_rule._best_candidate(pod, context)
        if candidate is None:
            return None
        if (
            not candidate.get("hpa_name")
            or not candidate.get("hpa")
            or not candidate.get("hpa_sequence")
        ):
            return None
        if not candidate.get("deployment_name") or not candidate.get("deployment"):
            return None

        namespace = self._namespace(pod)
        hpa_name = candidate["hpa_name"]
        deployment_name = candidate.get("deployment_name")
        actions = self._rescale_actions(
            timeline,
            hpa_name=hpa_name,
            deployment_name=deployment_name,
            namespace=namespace,
        )
        if len(actions) < self.MIN_RESCALE_EVENTS:
            return None

        timestamps = [
            action["timestamp"]
            for action in actions
            if isinstance(action.get("timestamp"), datetime)
        ]
        if len(timestamps) < 2:
            return None

        duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        if duration_seconds < self.MIN_DURATION_SECONDS:
            return None

        size_sequence: list[int] = []
        reasons: list[str] = []
        for action in actions:
            if not size_sequence or size_sequence[-1] != action["size"]:
                size_sequence.append(action["size"])
            reason = action.get("reason")
            if reason and reason not in reasons:
                reasons.append(reason)

        if len(size_sequence) < self.MIN_RESCALE_EVENTS:
            return None

        directions: list[str] = []
        for idx in range(1, len(size_sequence)):
            previous = size_sequence[idx - 1]
            current = size_sequence[idx]
            if current > previous:
                directions.append("up")
            elif current < previous:
                directions.append("down")

        if len(directions) < 3:
            return None
        if any(
            directions[idx] == directions[idx - 1] for idx in range(1, len(directions))
        ):
            return None

        behavior_context = self._behavior_context(candidate["hpa"])

        return {
            **candidate,
            "namespace": namespace,
            "workload_desc": self._target_display(candidate["hpa"], candidate),
            "rescale_actions": actions,
            "size_sequence": size_sequence,
            "duration_seconds": duration_seconds,
            "reason_messages": reasons,
            "behavior_context": behavior_context,
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
            raise ValueError("HPAThrashing explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        hpa_name = candidate["hpa_name"]
        workload_desc = candidate["workload_desc"]
        rs_name = candidate["rs_name"]
        pattern = candidate["pattern"]
        symptom = candidate["symptom"]
        minutes = candidate["duration_seconds"] / 60.0
        behavior_context = candidate.get("behavior_context", {}) or {}

        chain_causes = [
            Cause(
                code="HPA_THRASHING_PATTERN_OBSERVED",
                message=f"Timeline shows HPA '{hpa_name}' repeatedly rescaling {workload_desc}",
                role="temporal_context",
            ),
            Cause(
                code="HPA_REPLICA_DECISIONS_REVERSING",
                message="HorizontalPodAutoscaler keeps reversing desired replica recommendations instead of converging on a stable size",
                role="controller_root",
                blocking=True,
            ),
            Cause(
                code="WORKLOAD_CONTROLLER_APPLYING_REVERSALS",
                message=f"ReplicaSet '{rs_name}' keeps getting scaled up and down in response to those HPA decisions",
                role="controller_intermediate",
            ),
        ]

        if behavior_context.get("aggressive"):
            chain_causes.append(
                Cause(
                    code="HPA_DAMPING_REDUCED",
                    message="HPA behavior reduces or disables downscale damping, which makes flapping replica recommendations more likely",
                    role="controller_configuration",
                )
            )

        if symptom["kind"] == "deployment":
            chain_causes.append(
                Cause(
                    code="WORKLOAD_CAPACITY_UNSTABLE",
                    message=(
                        f"Deployment availability remains unstable at {symptom['available']}/{symptom['desired']} "
                        f"available replicas while autoscaling keeps reversing"
                    ),
                    role="workload_symptom",
                )
            )
        else:
            chain_causes.append(
                Cause(
                    code="WORKLOAD_CAPACITY_UNSTABLE",
                    message=(
                        f"ReplicaSet availability remains unstable at {symptom['available']}/{symptom['desired']} "
                        "available replicas while autoscaling keeps reversing"
                    ),
                    role="workload_symptom",
                )
            )

        evidence = [
            f"HPA '{hpa_name}' repeatedly rescaled {workload_desc} as: {' -> '.join(str(size) for size in candidate['size_sequence'])}",
            f"HPA rescale direction reversed {len(candidate['size_sequence']) - 1} times over {minutes:.1f} minutes",
            f"ReplicaSet '{rs_name}' was alternately scaled as: {' -> '.join(pattern['display'])}",
            symptom["message"],
        ]
        evidence.extend(behavior_context.get("evidence", []))

        if len(candidate.get("reason_messages", [])) >= 2:
            evidence.append(
                "SuccessfulRescale reasons flipped between opposing scaling signals within the same incident window"
            )

        object_evidence = {
            f"pod:{pod_name}": [f"Pod belongs to autoscaled workload {workload_desc}"],
            f"hpa:{hpa_name}": [
                f"scaleTargetRef={workload_desc}",
                f"SuccessfulRescale sizes alternated as {' -> '.join(str(size) for size in candidate['size_sequence'])}",
                f"rescaleEvents={len(candidate['rescale_actions'])}",
            ],
            f"replicaset:{rs_name}": [
                f"scaleUpEvents={pattern['up_count']}, scaleDownEvents={pattern['down_count']}",
                f"targetReplicaSizes={','.join(str(size) for size in pattern['unique_sizes'])}",
                f"availableReplicas={self._replica_oscillation_rule._available_replicas(candidate['rs'])}/{self._replica_oscillation_rule._current_replicas(candidate['rs'])}",
            ],
        }

        for item in behavior_context.get("object_items", []):
            if item not in object_evidence[f"hpa:{hpa_name}"]:
                object_evidence[f"hpa:{hpa_name}"].append(item)

        hpa_status = candidate["hpa"].get("status", {}) or {}
        current_replicas = self._as_int(hpa_status.get("currentReplicas"), -1)
        desired_replicas = self._as_int(hpa_status.get("desiredReplicas"), -1)
        min_replicas = self._as_int(
            candidate["hpa"].get("spec", {}).get("minReplicas"), -1
        )
        max_replicas = self._as_int(
            candidate["hpa"].get("spec", {}).get("maxReplicas"), -1
        )
        if current_replicas >= 0 and desired_replicas >= 0:
            object_evidence[f"hpa:{hpa_name}"].append(
                f"currentReplicas={current_replicas}, desiredReplicas={desired_replicas}, minReplicas={min_replicas}, maxReplicas={max_replicas}"
            )

        if symptom["kind"] == "deployment" and candidate.get("deployment_name"):
            deployment_name = candidate["deployment_name"]
            deployment = candidate.get("deployment") or {}
            object_evidence[f"deployment:{deployment_name}"] = [
                f"observedGeneration={self._as_int(deployment.get('status', {}).get('observedGeneration'), 0)}, generation={self._as_int(deployment.get('metadata', {}).get('generation'), 0)}",
                f"updatedReplicas={symptom['updated']}, availableReplicas={symptom['available']}, desiredReplicas={symptom['desired']}",
            ]

        confidence = 0.95
        if behavior_context.get("aggressive"):
            confidence = 0.97

        namespace = candidate["namespace"]
        ns_flag = f" -n {namespace}" if namespace else ""
        suggested_checks = [
            f"kubectl describe hpa {hpa_name}{ns_flag}",
            f"kubectl get hpa {hpa_name}{ns_flag} -o yaml",
            "kubectl get events --sort-by=.lastTimestamp",
            "Review HPA behavior.scaleDown stabilization and scaling policies for overly aggressive reversals",
        ]
        if candidate.get("deployment_name"):
            suggested_checks.insert(
                0,
                f"kubectl describe deployment {candidate['deployment_name']}{ns_flag}",
            )

        return {
            "root_cause": f"HPA '{hpa_name}' is thrashing the workload by repeatedly reversing replica recommendations",
            "confidence": confidence,
            "blocking": True,
            "causes": CausalChain(causes=chain_causes),
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "HPA behavior is too aggressive for this workload, especially if downscale stabilization is disabled or too short",
                "Metrics near the target threshold are noisy enough that the HPA keeps alternating between scale-up and scale-down decisions",
                "Pods take long enough to become Ready that the HPA reacts to transient startup utilization before capacity stabilizes",
                "Manual or GitOps writes to spec.replicas are fighting with the autoscaler control loop",
            ],
            "suggested_checks": suggested_checks,
        }
