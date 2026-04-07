from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class StatefulSetPartitionMisconfigurationRule(FailureRule):
    """
    Detects a RollingUpdate StatefulSet whose partition is configured high
    enough that no existing ordinal is eligible for update.

    Real-world behavior:
    - StatefulSet partitioned rollouts are commonly used for staged or canary
      updates, but leaving the partition at or above the replica count means
      the new revision is observed while zero Pods can transition
    - this is different from a normal partitioned rollout because no ordinal is
      actually eligible to begin updating
    - it is also different from an ordinal startup failure because
      `updatedReplicas` never moves above zero
    """

    name = "StatefulSetPartitionMisconfiguration"
    category = "Controller"
    priority = 62
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["statefulset"],
        "context": ["timeline"],
    }
    blocks = [
        "StatefulSetUpdateBlocked",
    ]

    WINDOW_MINUTES = 30
    MIN_PARTITION_EVENTS = 2
    MIN_STUCK_SECONDS = 300
    CACHE_KEY = "_statefulset_partition_misconfiguration_candidate"
    CONTROLLER_COMPONENTS = {
        "statefulset-controller",
        "kube-controller-manager",
    }
    PARTITION_MARKERS = (
        "partition",
        "partitioned",
        "rollingupdate",
        "rolling update",
        "0 pods updated",
        "no pods updated",
        "no pod is eligible",
        "no pods are eligible",
        "no ordinal is eligible",
    )
    TURNOVER_REASONS = {
        "successfulcreate",
        "successfuldelete",
        "recreatingfailedpod",
        "failedcreate",
    }
    TURNOVER_MARKERS = (
        "create pod",
        "delete pod",
        "recreate pod",
        "recreatingfailedpod",
    )

    def _as_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

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

    def _span_seconds(self, events: list[dict[str, Any]]) -> float:
        timestamps = [self._event_ts(event) for event in events]
        usable = [ts for ts in timestamps if ts is not None]
        if len(usable) < 2:
            return 0.0
        return (max(usable) - min(usable)).total_seconds()

    def _owning_statefulset_name(self, pod: dict[str, Any]) -> str | None:
        for owner in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if str(owner.get("kind", "")).lower() == "statefulset" and owner.get(
                "name"
            ):
                return str(owner["name"])
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

        namespace = self._namespace(pod)
        owner_name = self._owning_statefulset_name(pod)
        if owner_name:
            direct = sts_objects.get(owner_name)
            if isinstance(direct, dict) and self._namespace(direct) == namespace:
                return owner_name, direct

        for sts_name, sts in sts_objects.items():
            if not isinstance(sts, dict):
                continue
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

    def _partition_events(
        self,
        ordered_events: list[dict[str, Any]],
        sts_name: str,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        sts_name_lower = sts_name.lower()

        for event in ordered_events:
            component = self._source_component(event)
            if component and component not in self.CONTROLLER_COMPONENTS:
                continue

            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", "")).lower()
            involved_kind = str(involved.get("kind", "")).lower()
            message = self._event_message(event)

            if (
                sts_name_lower not in message
                and involved_name != sts_name_lower
                and not involved_name.startswith(f"{sts_name_lower}-")
            ):
                continue
            if not any(marker in message for marker in self.PARTITION_MARKERS):
                continue
            if involved_kind and involved_kind not in {"statefulset", "pod"}:
                continue

            matches.append(event)

        return matches

    def _turnover_after(
        self,
        ordered_events: list[dict[str, Any]],
        sts_name: str,
        after: datetime | None,
    ) -> bool:
        sts_name_lower = sts_name.lower()

        for event in ordered_events:
            event_ts = self._event_ts(event)
            if after is not None and event_ts is not None and event_ts <= after:
                continue

            component = self._source_component(event)
            if component and component not in self.CONTROLLER_COMPONENTS:
                continue

            message = self._event_message(event)
            reason = self._event_reason(event)
            involved = event.get("involvedObject", {}) or {}
            involved_name = str(involved.get("name", "")).lower()

            if (
                sts_name_lower not in message
                and involved_name != sts_name_lower
                and not involved_name.startswith(f"{sts_name_lower}-")
            ):
                continue

            if reason in self.TURNOVER_REASONS:
                return True
            if any(marker in message for marker in self.TURNOVER_MARKERS):
                return True

        return False

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
        metadata = sts.get("metadata", {}) or {}
        spec = sts.get("spec", {}) or {}
        status = sts.get("status", {}) or {}
        update_strategy = spec.get("updateStrategy", {}) or {}

        if update_strategy.get("type", "RollingUpdate") != "RollingUpdate":
            return None

        replicas = self._as_int(spec.get("replicas", status.get("replicas", 1)), 1)
        if replicas <= 0:
            return None

        partition = self._as_int(
            (update_strategy.get("rollingUpdate", {}) or {}).get("partition"),
            0,
        )
        if partition < replicas:
            return None

        current_revision = str(status.get("currentRevision", "")).strip()
        update_revision = str(status.get("updateRevision", "")).strip()
        if (
            not current_revision
            or not update_revision
            or current_revision == update_revision
        ):
            return None

        updated_replicas = self._as_int(status.get("updatedReplicas"), 0)
        if updated_replicas != 0:
            return None

        generation = self._as_int(metadata.get("generation"), 0)
        observed_generation = self._as_int(
            status.get("observedGeneration", generation),
            generation,
        )
        if generation and observed_generation and observed_generation < generation:
            return None

        ready_replicas = self._as_int(status.get("readyReplicas"), 0)
        current_replicas = self._as_int(
            status.get("currentReplicas", status.get("replicas", 0)),
            0,
        )
        if max(ready_replicas, current_replicas) <= 0:
            return None

        pod_name = str(pod.get("metadata", {}).get("name", "")).strip()
        if not pod_name:
            return None

        ordinal = self._pod_ordinal(pod_name, sts_name)
        if ordinal is None or ordinal >= replicas:
            return None

        pod_revision = self._pod_revision(pod)
        if pod_revision and current_revision and pod_revision != current_revision:
            return None

        ordered_events = self._ordered_recent(timeline)
        partition_events = self._partition_events(ordered_events, sts_name)
        if len(partition_events) < self.MIN_PARTITION_EVENTS:
            return None

        span_seconds = self._span_seconds(partition_events)
        if span_seconds < self.MIN_STUCK_SECONDS:
            return None

        first_partition_ts = self._event_ts(partition_events[0])
        if self._turnover_after(ordered_events, sts_name, first_partition_ts):
            return None

        highest_ordinal = replicas - 1

        return {
            "sts_name": sts_name,
            "pod_name": pod_name,
            "ordinal": ordinal,
            "replicas": replicas,
            "partition": partition,
            "highest_ordinal": highest_ordinal,
            "current_revision": current_revision,
            "update_revision": update_revision,
            "updated_replicas": updated_replicas,
            "current_replicas": current_replicas,
            "ready_replicas": ready_replicas,
            "generation": generation or observed_generation,
            "observed_generation": observed_generation,
            "pod_revision": pod_revision or current_revision,
            "event_count": len(partition_events),
            "span_seconds": span_seconds,
            "representative_message": str(
                partition_events[-1].get("message", "")
            ).strip(),
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
                "StatefulSetPartitionMisconfiguration explain() called without match"
            )

        sts_name = candidate["sts_name"]
        pod_name = candidate["pod_name"]
        ordinal = candidate["ordinal"]
        partition = candidate["partition"]
        replicas = candidate["replicas"]
        highest_ordinal = candidate["highest_ordinal"]
        current_revision = candidate["current_revision"]
        update_revision = candidate["update_revision"]
        updated_replicas = candidate["updated_replicas"]
        current_replicas = candidate["current_replicas"]
        ready_replicas = candidate["ready_replicas"]
        observed_generation = candidate["observed_generation"]
        generation = candidate["generation"]
        span_minutes = candidate["span_seconds"] / 60.0

        chain = CausalChain(
            causes=[
                Cause(
                    code="STATEFULSET_NEW_REVISION_OBSERVED",
                    message=f"StatefulSet '{sts_name}' has observed a new revision '{update_revision}' while existing Pods still run revision '{current_revision}'",
                    role="controller_context",
                ),
                Cause(
                    code="STATEFULSET_PARTITION_EXCLUDES_ALL_ORDINALS",
                    message=f"RollingUpdate partition {partition} is above the highest existing ordinal {highest_ordinal}, so no Pod is eligible for update",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="STATEFULSET_ROLLOUT_CANNOT_START",
                    message="The StatefulSet controller cannot begin the rolling update because zero ordinals satisfy the configured partition",
                    role="controller_intermediate",
                ),
                Cause(
                    code="STATEFULSET_RETAINED_OLD_REVISION",
                    message=f"All current replicas remain on the old revision and updatedReplicas is still {updated_replicas}",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "StatefulSet rollout cannot start because updateStrategy partition excludes every replica",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"StatefulSet '{sts_name}' has replicas={replicas} but RollingUpdate partition={partition}, so no existing ordinal qualifies for update",
                f"StatefulSet '{sts_name}' observed generation {observed_generation}/{generation or observed_generation} with currentRevision '{current_revision}' and updateRevision '{update_revision}'",
                f"updatedReplicas remains {updated_replicas} while currentReplicas={current_replicas} and readyReplicas={ready_replicas}",
                f"Observed {candidate['event_count']} recent partition-related controller event(s) over {span_minutes:.1f} minutes; latest: {candidate['representative_message']}",
                f"Pod '{pod_name}' remains on current revision '{candidate['pod_revision']}' because ordinal {ordinal} is below partition {partition}",
            ],
            "object_evidence": {
                f"statefulset:{sts_name}": [
                    f"partition={partition}, replicas={replicas}, highestOrdinal={highest_ordinal}",
                    f"currentRevision={current_revision}, updateRevision={update_revision}",
                    f"updatedReplicas={updated_replicas}, currentReplicas={current_replicas}, readyReplicas={ready_replicas}",
                ],
                f"pod:{pod_name}": [
                    f"ordinal={ordinal}",
                    f"controller-revision-hash={candidate['pod_revision']}",
                    f"Ordinal {ordinal} is below partition {partition}, so this Pod stays on revision '{current_revision}'",
                ],
            },
            "likely_causes": [
                "A canary or staged RollingUpdate partition was left at the replica count after an earlier maintenance step",
                "The partition value was copied from a larger StatefulSet or from a previous scale and now exceeds the highest live ordinal",
                "Automation patched spec.updateStrategy.rollingUpdate.partition to pause rollout but never lowered it to resume updates",
                "A manual StatefulSet edit introduced a new template revision while leaving the rollout partition set too high",
            ],
            "suggested_checks": [
                f"kubectl describe statefulset {sts_name}",
                f"kubectl get statefulset {sts_name} -o yaml",
                "Compare spec.updateStrategy.rollingUpdate.partition with the highest current ordinal and desired replica count",
                "Lower or remove the partition after confirming which ordinals should actually receive the new revision",
            ],
        }
