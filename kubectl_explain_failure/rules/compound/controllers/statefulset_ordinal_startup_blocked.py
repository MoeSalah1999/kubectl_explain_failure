from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class StatefulSetOrdinalStartupBlockedRule(FailureRule):
    """
    Detects StatefulSet rolling updates blocked because the current rollout
    ordinal has not completed startup, preventing ordered progress.

    Real-world behavior:
    - StatefulSet RollingUpdate advances one ordinal at a time in descending
      ordinal order; the controller waits for the current updated Pod to become
      Running and Ready before moving to the next lower ordinal
    - when the updated ordinal is stuck on startupProbe failure or init
      initialization failure, rollout progress stops even if older ordinals are
      still serving traffic on the previous revision
    - this rule summarizes that controller-level consequence instead of only
      reporting the local pod startup symptom
    """

    name = "StatefulSetOrdinalStartupBlocked"
    category = "Compound"
    priority = 74
    deterministic = False
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["statefulset"],
        "context": ["timeline"],
    }
    blocks = [
        "StatefulSetUpdateBlocked",
        "StartupProbeFailure",
        "InitContainerBlocksMain",
        "ContainerStartTimeout",
        "ProbeConflictStartupVsLiveness",
    ]

    WINDOW_MINUTES = 25
    MIN_STARTUP_OCCURRENCES = 2
    MIN_INCIDENT_SECONDS = 120
    CACHE_KEY = "_statefulset_ordinal_startup_blocked_candidate"
    CONTROLLER_REASONS = {"successfulcreate", "failedcreate", "recreatingfailedpod"}
    CONTROLLER_SOURCES = {"statefulset-controller"}
    INIT_FAILURE_REASONS = {
        "Error",
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
    }

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

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

    def _span_seconds(self, events: list[dict[str, Any]]) -> float:
        timestamps = [self._event_timestamp(event) for event in events]
        usable = [ts for ts in timestamps if ts is not None]
        if len(usable) < 2:
            return 0.0
        return (max(usable) - min(usable)).total_seconds()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _event_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _event_occurrences(self, event: dict[str, Any]) -> int:
        return max(1, self._as_int(event.get("count"), 1))

    def _owning_statefulset_name(self, pod: dict[str, Any]) -> str | None:
        for owner in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if str(owner.get("kind", "")).lower() == "statefulset":
                return str(owner.get("name", ""))
        return None

    def _find_statefulset(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> tuple[str, dict[str, Any]] | None:
        objects = context.get("objects", {}) or {}
        sts_objects = objects.get("statefulset", {}) or {}
        if not sts_objects:
            return None

        namespace = pod.get("metadata", {}).get("namespace", "default")
        owner_name = self._owning_statefulset_name(pod)
        if owner_name:
            direct = sts_objects.get(owner_name)
            if isinstance(direct, dict) and self._namespace(direct) == namespace:
                return owner_name, direct

        for sts_name, sts in sts_objects.items():
            if self._namespace(sts) != namespace:
                continue
            if owner_name and sts.get("metadata", {}).get("name") != owner_name:
                continue
            return sts_name, sts

        return None

    def _pod_ordinal(self, pod_name: str, sts_name: str) -> int | None:
        prefix = f"{sts_name}-"
        if not pod_name.startswith(prefix):
            return None
        suffix = pod_name[len(prefix) :]
        try:
            return int(suffix)
        except ValueError:
            return None

    def _pod_revision(self, pod: dict[str, Any]) -> str:
        labels = pod.get("metadata", {}).get("labels", {}) or {}
        return str(labels.get("controller-revision-hash", "")).strip()

    def _container_field_match(
        self, event: dict[str, Any], container_name: str
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        field_path = str(involved.get("fieldPath", "")).lower()
        if container_name.lower() in field_path:
            return True
        message = self._event_message(event)
        return (
            f'container "{container_name.lower()}"' in message
            or f"container {container_name.lower()}" in message
            or f"containers{{{container_name.lower()}}}" in message
        )

    def _configured_startup_containers(self, pod: dict[str, Any]) -> list[str]:
        containers = []
        for container in pod.get("spec", {}).get("containers", []) or []:
            if container.get("startupProbe") and container.get("name"):
                containers.append(str(container["name"]))
        return containers

    def _container_status(
        self, pod: dict[str, Any], container_name: str
    ) -> dict[str, Any]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if str(status.get("name", "")) == container_name:
                return status
        return {}

    def _startup_probe_candidate(
        self,
        pod: dict[str, Any],
        recent_events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        pod_name = str(pod.get("metadata", {}).get("name", ""))
        configured = self._configured_startup_containers(pod)
        if not configured:
            return None

        best: dict[str, Any] | None = None
        for container_name in configured:
            matching = []
            for event in recent_events:
                message = self._event_message(event)
                if "startup probe" not in message or "fail" not in message:
                    continue
                involved_name = str(
                    (event.get("involvedObject", {}) or {}).get("name", "")
                )
                if involved_name and involved_name != pod_name:
                    continue
                if len(configured) > 1 and not self._container_field_match(
                    event, container_name
                ):
                    continue
                matching.append(event)

            if not matching:
                continue

            status = self._container_status(pod, container_name)
            ready = bool(status.get("ready", False))
            restart_count = self._as_int(status.get("restartCount"), 0)
            state = status.get("state", {}) or {}
            state_name = (
                "waiting"
                if "waiting" in state
                else (
                    "running"
                    if "running" in state
                    else "terminated" if "terminated" in state else "unknown"
                )
            )
            occurrences = sum(self._event_occurrences(event) for event in matching)
            span_seconds = self._span_seconds(matching)

            if ready:
                continue
            if occurrences < self.MIN_STARTUP_OCCURRENCES and (
                restart_count < 1 or span_seconds < self.MIN_INCIDENT_SECONDS
            ):
                continue

            candidate = {
                "kind": "startup_probe",
                "container_name": container_name,
                "status_ready": ready,
                "restart_count": restart_count,
                "state_name": state_name,
                "events": matching,
                "occurrences": occurrences,
                "dominant_message": str(matching[-1].get("message", "")),
            }
            if best is None or candidate["occurrences"] > best["occurrences"]:
                best = candidate

        return best

    def _init_failure_candidate(
        self,
        pod: dict[str, Any],
        recent_events: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        pod_name = str(pod.get("metadata", {}).get("name", ""))

        for status in pod.get("status", {}).get("initContainerStatuses", []) or []:
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            terminated = state.get("terminated", {}) or {}
            reason = str(waiting.get("reason") or terminated.get("reason") or "")
            if reason not in self.INIT_FAILURE_REASONS:
                continue

            container_name = str(status.get("name", "<init>"))
            matching = [
                event
                for event in recent_events
                if (
                    (
                        (event.get("involvedObject", {}) or {}).get("name")
                        in {"", pod_name}
                        or pod_name.lower() in self._event_message(event)
                    )
                    and (
                        self._container_field_match(event, container_name)
                        or container_name.lower() in self._event_message(event)
                    )
                )
            ]

            return {
                "kind": "init_failure",
                "container_name": container_name,
                "reason": reason,
                "events": matching,
                "occurrences": max(
                    1, sum(self._event_occurrences(event) for event in matching)
                ),
                "dominant_message": (
                    str(
                        matching[-1].get(
                            "message", f"Init container {container_name} failed"
                        )
                    )
                    if matching
                    else f"Init container {container_name} failed with reason {reason}"
                ),
            }

        return None

    def _controller_rollout_events(
        self,
        recent_events: list[dict[str, Any]],
        pod_name: str,
        sts_name: str,
    ) -> list[dict[str, Any]]:
        result = []
        for event in recent_events:
            if self._event_reason(event) not in self.CONTROLLER_REASONS:
                continue
            if self._event_component(event) not in self.CONTROLLER_SOURCES:
                continue
            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", ""))
            message = self._event_message(event)
            if involved_name in {pod_name, sts_name}:
                result.append(event)
                continue
            if pod_name.lower() in message or sts_name.lower() in message:
                result.append(event)
        return result

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        found = self._find_statefulset(pod, context)
        if found is None:
            return None

        sts_name, sts = found
        pod_name = str(pod.get("metadata", {}).get("name", ""))
        ordinal = self._pod_ordinal(pod_name, sts_name)
        if ordinal is None:
            return None

        spec = sts.get("spec", {}) or {}
        status = sts.get("status", {}) or {}

        replicas = self._as_int(spec.get("replicas", 1), 1)
        update_strategy = spec.get("updateStrategy", {}) or {}
        if update_strategy.get("type", "RollingUpdate") != "RollingUpdate":
            return None

        partition = self._as_int(
            (update_strategy.get("rollingUpdate", {}) or {}).get("partition"),
            0,
        )
        allowed_updates = max(0, replicas - partition)
        updated_replicas = self._as_int(status.get("updatedReplicas"), 0)
        ready_replicas = self._as_int(status.get("readyReplicas"), 0)
        current_revision = str(status.get("currentRevision", "")).strip()
        update_revision = str(status.get("updateRevision", "")).strip()

        if (
            not update_revision
            or not current_revision
            or update_revision == current_revision
        ):
            return None
        if updated_replicas <= 0 or updated_replicas > allowed_updates:
            return None

        blocker_ordinal = replicas - updated_replicas
        if ordinal != blocker_ordinal:
            return None

        pod_revision = self._pod_revision(pod)
        if pod_revision and pod_revision != update_revision:
            return None

        recent_events = timeline.events_within_window(self.WINDOW_MINUTES)
        rollout_events = self._controller_rollout_events(
            recent_events, pod_name, sts_name
        )
        if not rollout_events:
            return None

        startup = self._startup_probe_candidate(
            pod, recent_events
        ) or self._init_failure_candidate(pod, recent_events)
        if startup is None:
            return None

        blocked_lower_ordinals = list(range(partition, ordinal))
        rollout_incomplete = (
            updated_replicas < allowed_updates or ready_replicas < replicas
        )
        if not rollout_incomplete:
            return None

        return {
            "sts_name": sts_name,
            "pod_name": pod_name,
            "ordinal": ordinal,
            "replicas": replicas,
            "updated_replicas": updated_replicas,
            "current_revision": current_revision,
            "update_revision": update_revision,
            "pod_revision": pod_revision or update_revision,
            "startup": startup,
            "rollout_events": rollout_events,
            "rollout_span_seconds": self._span_seconds(
                rollout_events + startup["events"]
            ),
            "blocked_lower_ordinals": blocked_lower_ordinals,
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
                "StatefulSetOrdinalStartupBlocked explain() called without match"
            )

        sts_name = candidate["sts_name"]
        pod_name = candidate["pod_name"]
        ordinal = candidate["ordinal"]
        update_revision = candidate["update_revision"]
        current_revision = candidate["current_revision"]
        updated_replicas = candidate["updated_replicas"]
        replicas = candidate["replicas"]
        startup = candidate["startup"]
        span_minutes = candidate["rollout_span_seconds"] / 60.0

        lower_text = ", ".join(
            str(value) for value in candidate["blocked_lower_ordinals"]
        )
        if lower_text:
            blocked_message = f"Lower ordinals {lower_text} cannot advance to revision '{update_revision}' until ordinal {ordinal} becomes Ready"
        else:
            blocked_message = f"StatefulSet rollout cannot complete until ordinal {ordinal} becomes Ready on revision '{update_revision}'"

        if startup["kind"] == "startup_probe":
            startup_context = f"Container '{startup['container_name']}' on ordinal {ordinal} is still failing startupProbe checks"
            likely_causes = [
                "The new StatefulSet revision introduced an application or configuration regression that prevents the updated ordinal from completing startup",
                "The startupProbe budget is too short for the workload's real initialization or recovery time on the updated revision",
                "The ordinal-specific data set or migration path for this replica makes startup slower or more failure-prone than other replicas",
                "A dependency, secret, or local volume assumption changed in the new revision and only surfaces once the updated ordinal starts",
            ]
        else:
            startup_context = f"Init container '{startup['container_name']}' failed before ordinal {ordinal} could start its main workload"
            likely_causes = [
                "The new StatefulSet revision added an init step or migration that fails before the ordinal can become Ready",
                "The init container depends on credentials, storage, or network state that is no longer valid for the updated revision",
                "An ordinal-specific bootstrap task is failing and preventing the StatefulSet controller from advancing rollout order",
            ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="STATEFULSET_ROLLING_UPDATE_ACTIVE",
                    message=f"StatefulSet '{sts_name}' is rolling from revision '{current_revision}' to '{update_revision}'",
                    role="controller_context",
                ),
                Cause(
                    code="STATEFULSET_ORDINAL_STARTUP_BLOCKED",
                    message=startup_context,
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="STATEFULSET_ORDERED_PROGRESS_BLOCKED",
                    message=blocked_message,
                    role="controller_intermediate",
                ),
                Cause(
                    code="STATEFULSET_ROLLOUT_STALLED",
                    message=f"StatefulSet rollout remains split at {updated_replicas}/{replicas} updated replicas",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"StatefulSet '{sts_name}' is split between revisions '{current_revision}' and '{update_revision}' with {updated_replicas}/{replicas} replicas updated",
            f"Pod '{pod_name}' is ordinal {ordinal} and is the current ordered rollout gate for revision '{update_revision}'",
            f"Recent rollout and startup signals for ordinal {ordinal} persisted for {span_minutes:.1f} minutes",
            startup["dominant_message"],
        ]

        object_evidence = {
            f"statefulset:{sts_name}": [
                f"currentRevision={current_revision}",
                f"updateRevision={update_revision}",
                f"updatedReplicas={updated_replicas}/{replicas}",
            ],
            f"pod:{pod_name}": [
                f"ordinal={ordinal}",
                f"controller-revision-hash={candidate['pod_revision']}",
                blocked_message,
            ],
            f"container:{startup['container_name']}": [startup["dominant_message"]],
        }

        if startup["kind"] == "startup_probe":
            object_evidence[f"pod:{pod_name}"].append(
                f"ready={startup['status_ready']}, state={startup['state_name']}, restartCount={startup['restart_count']}"
            )
        else:
            object_evidence[f"pod:{pod_name}"].append(
                f"Init failure reason={startup['reason']}"
            )

        return {
            "root_cause": f"StatefulSet ordered rollout is blocked because ordinal {ordinal} cannot finish startup",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": [
                f"kubectl describe statefulset {sts_name}",
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {startup['container_name']} --previous",
                "Compare currentRevision and updateRevision and inspect the highest updated ordinal before proceeding with lower ordinals",
            ],
        }
