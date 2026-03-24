from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PreemptionIneffectiveDueToTopologySpreadRule(FailureRule):
    """
    Detects FailedScheduling loops where topology spread constraints remain
    unsatisfied even after the scheduler considers preemption.

    Real-world interpretation:
    - The Pod has hard topologySpreadConstraints
    - Scheduler retries placement and considers preemption
    - Preemption is not helpful because topology spread rules still cannot
      be satisfied
    """

    name = "PreemptionIneffectiveDueToTopologySpread"
    category = "Scheduling"
    priority = 90
    deterministic = True
    blocks = [
        "SchedulerPreemptionLoop",
        "TopologySpreadUnsatisfiable",
        "FailedScheduling",
        "InsufficientResources",
    ]
    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    PREEMPTION_MARKERS = (
        "preemption:",
        "preemption is not helpful",
        "no preemption victims found for incoming pod",
        "preempt",
    )

    TOPOLOGY_MARKERS = (
        "topology spread",
        "topology spread constraints",
        "didn't match pod's topology spread constraints",
        "didn't match pod topology spread constraints",
        "cannot satisfy topology spread",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _has_hard_topology_constraints(self, pod) -> bool:
        constraints = pod.get("spec", {}).get("topologySpreadConstraints", [])
        return any(
            constraint.get("whenUnsatisfiable") == "DoNotSchedule"
            for constraint in constraints
        )

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        if not self._has_hard_topology_constraints(pod):
            return False

        recent = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent:
            return False

        matched_events = 0
        total_failures = 0
        repeated_signal = False

        for event in recent:
            message = str(event.get("message", "")).lower()
            occurrences = self._occurrences(event)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            has_preemption = any(
                marker in message for marker in self.PREEMPTION_MARKERS
            )
            has_topology = any(marker in message for marker in self.TOPOLOGY_MARKERS)

            if has_preemption and has_topology:
                matched_events += occurrences

        if matched_events < 2:
            return False
        if total_failures < 3:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < 45 and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        dominant_msg = None
        if timeline:
            messages = [
                str(event.get("message", ""))
                for event in timeline.events_within_window(
                    15, reason="FailedScheduling"
                )
                if event.get("message")
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_CONSTRAINT",
                    message="Topology spread constraints restrict valid node placement",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="PREEMPTION_INEFFECTIVE",
                    message="Preemption cannot create a placement that satisfies topology constraints",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler rejects all nodes due to unsatisfied topology constraints",
                    role="scheduling_decision",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because topology spread constraints stay unsatisfied",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Preemption is ineffective because topology spread constraints cannot be satisfied",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "FailedScheduling events include both preemption attempts and topology spread constraint violations",
                "Multiple scheduling retries within short window",
                "Scheduler indicates preemption is not helpful",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Topology spread constraints are too strict for current cluster state",
                "Insufficient nodes across required topology domains",
                "Uneven pod distribution prevents restoring the required spread",
                "Preemption cannot change the topology-domain imbalance",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check topologySpreadConstraints in pod spec",
                "Verify topologyKey labels exist on nodes",
                "Evaluate maxSkew and whenUnsatisfiable settings",
                "Inspect the distribution of matching pods across topology domains",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Topology spread constraints prevent scheduling even with preemption"
                ]
            },
        }
