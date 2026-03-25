from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SchedulingConstraintOscillationRule(FailureRule):
    """
    Detects pods whose FailedScheduling reasons alternate between distinct
    constraint families over time, indicating unstable or shifting placement
    feasibility rather than one persistent blocker.

    Example:
    node affinity mismatch -> insufficient cpu -> node affinity mismatch -> insufficient cpu
    """

    name = "SchedulingConstraintOscillation"
    category = "Temporal"
    priority = 72
    deterministic = False
    blocks = [
        "RepeatedSchedulingBackoff",
        "SchedulingTimeoutExceeded",
        "FailedScheduling",
    ]
    requires = {"context": ["timeline"]}
    phases = ["Pending"]

    threshold_cycles: int = 2
    window_minutes: int = 15
    min_duration_seconds: int = 180

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

    def _relevant_events(self, timeline: Timeline) -> list[dict]:
        scheduling_events = timeline.events_within_window(
            self.window_minutes, reason="FailedScheduling"
        )
        filtered = []
        for event in scheduling_events:
            source = self._source_component(event)
            if source and "scheduler" not in source:
                continue
            filtered.append(event)
        return filtered

    def _family_sequence(self, events: list[dict]) -> list[str]:
        sequence: list[str] = []
        for event in events:
            category = self._classify(str(event.get("message", "")))
            if not category:
                continue
            if not sequence or sequence[-1] != category:
                sequence.append(category)
        return sequence

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        scheduling_events = self._relevant_events(timeline)
        if len(scheduling_events) < 4:
            return False

        sequence = self._family_sequence(scheduling_events)
        if len(sequence) < 4:
            return False
        if len(set(sequence)) != 2:
            return False

        total_occurrences = 0
        for event in scheduling_events:
            total_occurrences += self._occurrences(event)
        if total_occurrences < 4:
            return False

        cycles = 0
        for idx in range(2, len(sequence)):
            if (
                sequence[idx] == sequence[idx - 2]
                and sequence[idx] != sequence[idx - 1]
            ):
                cycles += 1

        if cycles < self.threshold_cycles:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < self.min_duration_seconds:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod: dict, events: list[dict], context: dict) -> dict:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError(
                "SchedulingConstraintOscillation requires a Timeline context"
            )
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        scheduling_events = self._relevant_events(timeline)
        sequence = self._family_sequence(scheduling_events)
        message_counts: dict[str, int] = {}

        for event in scheduling_events:
            if event.get("message"):
                message = str(event.get("message"))
                message_counts[message] = message_counts.get(message, 0) + 1

        duration_seconds = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        dominant_message = None
        if message_counts:
            best_count = max(message_counts.values())
            for event in scheduling_events:
                message = str(event.get("message", ""))
                if message_counts.get(message) == best_count:
                    dominant_message = message
                    break

        chain = CausalChain(
            causes=[
                Cause(
                    code="SCHEDULING_FAILURE_PATTERN_OBSERVED",
                    message=f"Scheduler emitted alternating FailedScheduling categories: {' -> '.join(sequence)}",
                    role="temporal_context",
                ),
                Cause(
                    code="SCHEDULING_CONSTRAINT_OSCILLATION",
                    message="Different scheduling constraint families alternated across retries without converging",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PLACEMENT_FEASIBILITY_UNSTABLE",
                    message="Placement feasibility shifted between competing constraint classes instead of converging",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending while scheduler encounters changing constraint failures",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Scheduling constraints oscillated across retries instead of converging on a stable blocker",
            "confidence": 0.9,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"FailedScheduling categories alternated as: {' -> '.join(sequence)}",
                f"Oscillation persisted for {duration_seconds/60:.1f} minutes",
                "Multiple distinct scheduling constraint families were observed",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_message]
                    if dominant_message
                    else []
                ),
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Scheduler alternated between different scheduling constraint families over time"
                ]
            },
            "likely_causes": [
                "Different schedulability constraints are surfacing as cluster state changes between retries",
                "Capacity and placement policy are both contributing to an unstable scheduling outcome",
                "The pod is affected by multiple competing scheduling blockers rather than one stable cause",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "Inspect affinity, topology, taints, and resource requests together",
                "Check whether cluster state is changing between scheduler retries",
            ],
        }
