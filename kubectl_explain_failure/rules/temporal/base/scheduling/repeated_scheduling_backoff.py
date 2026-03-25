from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class RepeatedSchedulingBackoffRule(FailureRule):
    """
    Detects pods that repeatedly re-enter the scheduler with the same
    unresolved scheduling blocker over a short period of time.

    Real-world interpretation:
    - kube-scheduler does not usually emit a literal "BackOff" event for
      scheduling failures
    - instead, the same FailedScheduling decision is retried over and over,
      often coalesced through event `count`
    - this rule models that retry/backoff behavior as repeated failures with
      a stable dominant constraint family
    """

    name = "RepeatedSchedulingBackoff"
    category = "Temporal"
    priority = 68
    deterministic = False
    blocks = ["SchedulingTimeoutExceeded", "FailedScheduling"]
    requires = {"context": ["timeline"]}
    phases = ["Pending"]

    threshold_occurrences: int = 4
    window_minutes: int = 10
    min_duration_seconds: int = 120

    SPECIFIC_MARKERS = (
        "preemption:",
        "preemption is not helpful",
        "no preemption victims found for incoming pod",
        "poddisruptionbudget",
        "would violate",
        "cannot evict pod",
        "topology spread",
        "topology spread constraints",
        "volume binding",
        "waitforfirstconsumer",
        "persistentvolumeclaim",
        "pvc",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _source_component(self, event) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _classify(self, message: str) -> str | None:
        msg = message.lower()

        if "insufficient" in msg or "too many pods" in msg:
            return "resource"
        if (
            "node affinity" in msg
            or "anti-affinity" in msg
            or "pod affinity" in msg
            or "node selector" in msg
        ):
            return "affinity"
        if "topology spread" in msg or "topology" in msg:
            return "topology"
        if "taint" in msg or "tolerat" in msg:
            return "taint"
        if "volume" in msg or "persistentvolumeclaim" in msg or "pvc" in msg:
            return "volume"
        if "hostport" in msg or "host port" in msg:
            return "hostport"

        return None

    def _normalized_message(self, message: str) -> str:
        return " ".join(str(message).lower().split())

    def _has_specific_failure_semantics(self, message: str) -> bool:
        normalized = self._normalized_message(message)
        if any(marker in normalized for marker in self.SPECIFIC_MARKERS):
            return True
        return self._classify(normalized) is not None

    def _relevant_events(self, timeline: Timeline) -> list[dict]:
        recent_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )
        filtered = []
        for event in recent_events:
            source = self._source_component(event)
            if source and "scheduler" not in source:
                continue
            if not str(event.get("message", "")).strip():
                continue
            filtered.append(event)
        return filtered

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        relevant_events = self._relevant_events(timeline)
        if len(relevant_events) < 2:
            return False

        key_totals: dict[str, int] = {}
        family_sequence: list[str] = []
        total_occurrences = 0
        repeated_signal = False

        for event in relevant_events:
            message = str(event.get("message", ""))
            if self._has_specific_failure_semantics(message):
                return False
            category = "generic"
            key = self._normalized_message(message)

            occurrences = self._occurrences(event)
            total_occurrences += occurrences
            if occurrences >= 2:
                repeated_signal = True

            key_totals[key] = key_totals.get(key, 0) + occurrences
            if not family_sequence or family_sequence[-1] != category:
                family_sequence.append(category)

        if total_occurrences < self.threshold_occurrences:
            return False
        if len(key_totals) != 1:
            return False
        if len(set(family_sequence)) != 1:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < self.min_duration_seconds and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod: dict, events: list[dict], context: dict) -> dict:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("RepeatedSchedulingBackoff requires a Timeline context")
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        relevant_events = self._relevant_events(timeline)
        total_occurrences = 0
        category_counts: dict[str, int] = {}
        message_counts: dict[str, int] = {}
        original_messages: dict[str, str] = {}

        for event in relevant_events:
            message = str(event.get("message", ""))
            category = "generic"
            total_occurrences += self._occurrences(event)
            category_counts[category] = category_counts.get(
                category, 0
            ) + self._occurrences(event)
            normalized = self._normalized_message(message)
            message_counts[normalized] = message_counts.get(
                normalized, 0
            ) + self._occurrences(event)
            original_messages.setdefault(normalized, message)

        dominant_category = "<unknown>"
        dominant_message = None
        if category_counts:
            dominant_category = max(
                category_counts.items(),
                key=lambda item: item[1],
            )[0]
        if message_counts:
            best_count = max(message_counts.values())
            for event in relevant_events:
                normalized = self._normalized_message(str(event.get("message", "")))
                if message_counts.get(normalized) == best_count:
                    dominant_message = original_messages.get(
                        normalized, str(event.get("message", ""))
                    )
                    break

        duration_seconds = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPEATED_SCHEDULER_RETRIES",
                    message=f"Scheduler retried FailedScheduling {total_occurrences} times within {self.window_minutes} minutes",
                    role="temporal_context",
                ),
                Cause(
                    code="SCHEDULING_BACKOFF_LOOP",
                    message=f"Scheduler repeatedly retried the same {dominant_category} scheduling blocker without progress",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PERSISTENT_SCHEDULING_REJECTION",
                    message="The same scheduling constraint kept re-queueing the Pod without progress",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending while scheduler retries the same unresolved placement decision",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Scheduler repeatedly backed off while retrying the same unresolved scheduling constraint",
            "confidence": 0.89,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"FailedScheduling retries observed {total_occurrences} times within {self.window_minutes} minutes",
                f"Dominant scheduling blocker category remained stable: {dominant_category}",
                f"Sustained retry duration: {duration_seconds/60:.1f} minutes",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_message]
                    if dominant_message
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"Scheduler repeatedly retried the same {dominant_category} scheduling failure"
                ]
            },
            "likely_causes": [
                "A single scheduling blocker remained unresolved across multiple scheduler retries",
                "Autoscaling or capacity changes did not arrive quickly enough to satisfy the Pod",
                "The scheduler kept re-queueing the Pod without any meaningful state change",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "Check whether the dominant scheduling blocker is capacity, affinity, taints, or storage",
                "Inspect whether cluster autoscaler or provisioning is making progress",
            ],
        }
