from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.temporal.base.controllers.replica_oscillation import (
    ReplicaOscillationRule,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class HPAConflictsWithManualScalingRule(FailureRule):
    """
    Detect an HPA that is fighting with manual or external writes to replicas.

    Real-world behavior:
    - HPA regularly writes the scale subresource of its target, while operators
      or GitOps tools sometimes keep writing `spec.replicas` or `/scale`
    - this creates a control-loop ownership fight where the Deployment keeps
      moving between the HPA-requested size and the external size
    - managedFields give a strong source of truth for who last touched the
      scale path, so this rule prefers them over guessing from event text alone
    """

    name = "HPAConflictsWithManualScaling"
    category = "Compound"
    priority = 78
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["hpa", "replicaset", "deployment"],
        "context": ["timeline"],
    }
    blocks = [
        "HPAThrashing",
        "ReplicaOscillation",
        "DeploymentReplicaMismatch",
        "DeploymentRolloutStalled",
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetUnavailable",
    ]

    WINDOW_MINUTES = 30
    MIN_HPA_RESCALES = 2
    MIN_MANUAL_WRITES = 1
    MIN_SCALE_REVERSALS = 3
    MIN_INCIDENT_SECONDS = 300
    CACHE_KEY = "_hpa_conflicts_with_manual_scaling_candidate"
    HPA_COMPONENTS = {
        "horizontal-pod-autoscaler",
        "horizontal-pod-autoscaler-controller",
    }
    SYSTEM_MANAGERS = {
        "horizontal-pod-autoscaler",
        "kube-controller-manager",
        "deployment-controller",
        "replicaset-controller",
        "statefulset-controller",
    }
    EXTERNAL_MANAGER_MARKERS = (
        "kubectl",
        "argocd",
        "argo-cd",
        "flux",
        "helm",
        "terraform",
        "pulumi",
        "ansible",
        "gitops",
        "kustomize",
    )
    RESCALE_SIZE_RE = re.compile(r"new size:\s*(\d+)", re.IGNORECASE)

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

    def _hpa_unhealthy(self, hpa: dict[str, Any]) -> bool:
        for condition in hpa.get("status", {}).get("conditions", []) or []:
            cond_type = str(condition.get("type", ""))
            if cond_type not in {"AbleToScale", "ScalingActive"}:
                continue
            if self._is_false(condition.get("status")):
                return True
        return False

    def _fields_touch_replicas(self, value: Any) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key == "f:replicas":
                    return True
                if self._fields_touch_replicas(nested):
                    return True
        elif isinstance(value, list):
            for item in value:
                if self._fields_touch_replicas(item):
                    return True
        return False

    def _is_external_manager(self, manager: str) -> bool:
        manager_norm = manager.strip().lower()
        if not manager_norm:
            return False
        if manager_norm in self.SYSTEM_MANAGERS:
            return False
        if "horizontal-pod-autoscaler" in manager_norm:
            return False
        if "controller" in manager_norm and "argocd" not in manager_norm:
            return False
        return True

    def _external_scale_writes(
        self,
        workload: dict[str, Any],
        *,
        incident_start: datetime,
        incident_end: datetime,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for entry in workload.get("metadata", {}).get("managedFields", []) or []:
            if not isinstance(entry, dict):
                continue

            manager = self._message(entry.get("manager"))
            if not self._is_external_manager(manager):
                continue

            subresource = self._message(entry.get("subresource"))
            fields_v1 = entry.get("fieldsV1")
            if subresource != "scale" and not self._fields_touch_replicas(fields_v1):
                continue

            ts = self._parse_ts(entry.get("time"))
            if ts is None:
                continue
            if ts < incident_start - timedelta(minutes=5):
                continue
            if ts > incident_end + timedelta(minutes=5):
                continue

            category = "manual_or_external"
            manager_norm = manager.lower()
            if any(marker in manager_norm for marker in self.EXTERNAL_MANAGER_MARKERS):
                category = "manual_or_gitops"

            results.append(
                {
                    "manager": manager,
                    "timestamp": ts,
                    "subresource": subresource or "<spec>",
                    "category": category,
                }
            )

        results.sort(
            key=lambda item: item["timestamp"]
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return results

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

            actions.append(
                {
                    "size": self._as_int(size_match.group(1), 0),
                    "timestamp": self._event_ts(event),
                    "message": message,
                }
            )

        actions.sort(
            key=lambda item: item.get("timestamp")
            or datetime.min.replace(tzinfo=timezone.utc)
        )
        return actions

    def _best_scale_pattern(
        self,
        timeline: Timeline,
        *,
        deployment_name: str,
        workload_rs: dict[str, dict[str, Any]],
        deployment: dict[str, Any],
    ) -> dict[str, Any] | None:
        actions = self._replica_oscillation_rule._scale_actions(
            timeline,
            deployment_name=deployment_name,
            replicaset_names=set(workload_rs),
        )
        if len(actions) < 3:
            return None

        best: dict[str, Any] | None = None
        best_score = (-1, -1.0)
        for rs_name, rs in workload_rs.items():
            rs_actions = [action for action in actions if action["rs_name"] == rs_name]
            pattern = self._replica_oscillation_rule._pattern_details(rs_actions)
            if pattern is None:
                continue
            symptom = self._replica_oscillation_rule._deployment_symptom(
                deployment_name, deployment
            )
            if symptom is None:
                symptom = self._replica_oscillation_rule._replicaset_symptom(
                    rs_name, rs
                )
            if symptom is None:
                continue

            timestamps = [
                action["timestamp"]
                for action in pattern["collapsed"]
                if isinstance(action.get("timestamp"), datetime)
            ]
            if len(timestamps) < 2:
                continue
            duration_seconds = (max(timestamps) - min(timestamps)).total_seconds()
            score = (len(pattern["collapsed"]), duration_seconds)
            if score > best_score:
                best_score = score
                best = {
                    "rs_name": rs_name,
                    "rs": rs,
                    "pattern": pattern,
                    "symptom": symptom,
                    "incident_start": min(timestamps),
                    "incident_end": max(timestamps),
                    "duration_seconds": duration_seconds,
                }
        return best

    def _candidate(
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

        deployment_entry = self._replica_oscillation_rule._candidate_deployment(
            pod,
            deployments,
            replicasets,
        )
        if deployment_entry is None:
            return None

        deployment_name, deployment = deployment_entry
        workload_rs = self._replica_oscillation_rule._owned_replicasets(
            deployment_name,
            self._namespace(deployment),
            replicasets,
        )
        if not workload_rs:
            return None

        scale_pattern = self._best_scale_pattern(
            timeline,
            deployment_name=deployment_name,
            workload_rs=workload_rs,
            deployment=deployment,
        )
        if scale_pattern is None:
            return None
        if scale_pattern["duration_seconds"] < self.MIN_INCIDENT_SECONDS:
            return None
        if scale_pattern["pattern"]["direction_changes"] < self.MIN_SCALE_REVERSALS:
            return None

        namespace = self._namespace(deployment)
        hpa_candidate = self._replica_oscillation_rule._candidate_hpa(
            context,
            deployment_name=deployment_name,
            namespace=namespace,
        )
        if hpa_candidate is None:
            return None

        hpa_name, hpa = hpa_candidate
        if self._hpa_unhealthy(hpa):
            return None

        rescale_actions = self._rescale_actions(
            timeline,
            hpa_name=hpa_name,
            deployment_name=deployment_name,
            namespace=namespace,
        )
        if len(rescale_actions) < self.MIN_HPA_RESCALES:
            return None

        incident_start = min(
            scale_pattern["incident_start"],
            *[
                action["timestamp"]
                for action in rescale_actions
                if isinstance(action.get("timestamp"), datetime)
            ],
        )
        incident_end = max(
            scale_pattern["incident_end"],
            *[
                action["timestamp"]
                for action in rescale_actions
                if isinstance(action.get("timestamp"), datetime)
            ],
        )

        external_writes = self._external_scale_writes(
            deployment,
            incident_start=incident_start,
            incident_end=incident_end,
        )
        if len(external_writes) < self.MIN_MANUAL_WRITES:
            return None

        spec_replicas = self._as_int(deployment.get("spec", {}).get("replicas"), 0)
        status = deployment.get("status", {}) or {}
        status_replicas = self._as_int(status.get("replicas"), spec_replicas)
        available_replicas = self._as_int(
            status.get("availableReplicas", status.get("readyReplicas", 0)), 0
        )
        updated_replicas = self._as_int(status.get("updatedReplicas"), 0)

        hpa_status = hpa.get("status", {}) or {}
        hpa_current = self._as_int(hpa_status.get("currentReplicas"), -1)
        hpa_desired = self._as_int(hpa_status.get("desiredReplicas"), -1)
        current_diverges = hpa_desired >= 0 and hpa_desired != spec_replicas
        if not current_diverges and len(external_writes) < 2:
            return None

        hpa_sizes = [action["size"] for action in rescale_actions]
        if not hpa_sizes:
            return None

        return {
            "deployment_name": deployment_name,
            "deployment": deployment,
            "namespace": namespace,
            "rs_name": scale_pattern["rs_name"],
            "rs": scale_pattern["rs"],
            "pattern": scale_pattern["pattern"],
            "symptom": scale_pattern["symptom"],
            "duration_seconds": (incident_end - incident_start).total_seconds(),
            "incident_start": incident_start,
            "incident_end": incident_end,
            "hpa_name": hpa_name,
            "hpa": hpa,
            "rescale_actions": rescale_actions,
            "hpa_sizes": hpa_sizes,
            "external_writes": external_writes,
            "spec_replicas": spec_replicas,
            "status_replicas": status_replicas,
            "available_replicas": available_replicas,
            "updated_replicas": updated_replicas,
            "hpa_current": hpa_current,
            "hpa_desired": hpa_desired,
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
                "HPAConflictsWithManualScaling explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        deployment_name = candidate["deployment_name"]
        hpa_name = candidate["hpa_name"]
        rs_name = candidate["rs_name"]
        pattern = candidate["pattern"]
        minutes = candidate["duration_seconds"] / 60.0
        managers = [item["manager"] for item in candidate["external_writes"]]
        unique_managers = list(dict.fromkeys(managers))
        manager_display = ", ".join(unique_managers)

        chain = CausalChain(
            causes=[
                Cause(
                    code="AUTOSCALER_AND_EXTERNAL_SCALE_WRITES_OBSERVED",
                    message=(
                        f"HPA '{hpa_name}' and external scale writers both updated "
                        f"Deployment/{deployment_name} during the same incident window"
                    ),
                    role="controller_context",
                ),
                Cause(
                    code="HPA_MANUAL_SCALING_CONFLICT",
                    message=(
                        "HorizontalPodAutoscaler is fighting with manual or GitOps "
                        "replica changes on the same workload"
                    ),
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="EXTERNAL_SCALE_WRITES_OVERRIDE_AUTOSCALER",
                    message=(
                        f"External manager(s) {manager_display} kept writing the "
                        "replica count after HPA reconciliation"
                    ),
                    role="controller_intermediate",
                ),
                Cause(
                    code="WORKLOAD_CAPACITY_UNSTABLE",
                    message=(
                        f"Deployment availability remains unstable at "
                        f"{candidate['available_replicas']}/{candidate['spec_replicas']} "
                        "while competing scale writers keep changing desired size"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"HPA '{hpa_name}' targets Deployment/{deployment_name} and rescaled it as: {' -> '.join(str(size) for size in candidate['hpa_sizes'])}",
            f"Deployment/{deployment_name} managedFields show {len(candidate['external_writes'])} recent external replica write(s) by {manager_display}",
            f"ReplicaSet '{rs_name}' was alternately scaled as: {' -> '.join(pattern['display'])}",
            (
                f"Deployment '{deployment_name}' currently asks for {candidate['spec_replicas']} replicas "
                f"while HPA status still wants {candidate['hpa_desired']}"
            ),
            (
                f"Scale ownership conflict lasted {minutes:.1f} minutes with "
                f"{pattern['direction_changes']} controller scale reversals"
            ),
        ]
        if candidate["symptom"]["message"] not in evidence:
            evidence.append(candidate["symptom"]["message"])

        object_evidence = {
            f"pod:{pod_name}": [
                f"Pod belongs to HPA-managed workload Deployment/{deployment_name}"
            ],
            f"hpa:{hpa_name}": [
                f"scaleTargetRef=Deployment/{deployment_name}",
                f"SuccessfulRescale sizes observed as {' -> '.join(str(size) for size in candidate['hpa_sizes'])}",
                (
                    f"currentReplicas={candidate['hpa_current']}, "
                    f"desiredReplicas={candidate['hpa_desired']}"
                ),
            ],
            f"deployment:{deployment_name}": [
                f"specReplicas={candidate['spec_replicas']}, statusReplicas={candidate['status_replicas']}",
                f"updatedReplicas={candidate['updated_replicas']}, availableReplicas={candidate['available_replicas']}",
                f"externalScaleManagers={manager_display}",
            ],
            f"replicaset:{rs_name}": [
                f"scaleUpEvents={pattern['up_count']}, scaleDownEvents={pattern['down_count']}",
                f"targetReplicaSizes={','.join(str(size) for size in pattern['unique_sizes'])}",
            ],
        }

        last_external = candidate["external_writes"][-1]
        object_evidence[f"deployment:{deployment_name}"].append(
            f"lastExternalScaleWrite={last_external['manager']} at {last_external['timestamp'].isoformat().replace('+00:00', 'Z')}"
        )

        namespace = candidate["namespace"]
        ns_flag = f" -n {namespace}" if namespace else ""
        return {
            "root_cause": (
                f"HPA '{hpa_name}' is conflicting with manual or GitOps replica "
                f"changes on Deployment/{deployment_name}"
            ),
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Someone used `kubectl scale` or patched replicas directly while the HPA was still active",
                "A GitOps or delivery controller is continuously reconciling `spec.replicas` on a workload that is also managed by HPA",
                "An emergency manual scale change was left in place instead of disabling or removing the HPA first",
                "Multiple automation systems are writing the scale subresource and Deployment spec at the same time",
            ],
            "suggested_checks": [
                f"kubectl get deployment {deployment_name}{ns_flag} -o yaml --show-managed-fields",
                f"kubectl describe hpa {hpa_name}{ns_flag}",
                "Remove `spec.replicas` from GitOps-managed manifests for HPA-controlled workloads or suspend the HPA before manual scaling",
                "Audit recent scale or patch commands and delivery-controller reconciliations during the incident window",
            ],
        }
