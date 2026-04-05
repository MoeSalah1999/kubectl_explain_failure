from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule


class PendingUnschedulableRule(FailureRule):
    """
    Detects Pods that remain Pending because the scheduler cannot
    place them onto any Node due to unschedulable conditions.

    Signals:
    - Pod phase is Pending
    - FailedScheduling events observed
    - Node conditions indicate DiskPressure or MemoryPressure
    - No PVC-level blocking condition detected

    Interpretation:
    The scheduler is unable to bind the Pod to any available Node.
    This may be due to resource exhaustion, node pressure conditions,
    taints, or other scheduling constraints. The Pod remains Pending
    because no feasible scheduling decision can be made.

    Scope:
    - Scheduling + infrastructure layer
    - Deterministic (event timeline + node condition correlation)
    - Acts as a compound unschedulable aggregation rule when no
    higher-priority PVC or controller rule explains the Pending state

    Exclusions:
    - Does not include PVC provisioning or volume binding failures
    - Does not include controller rollout stalls
    - Does not include post-scheduling container runtime failures
    """

    name = "PendingUnschedulable"
    category = "Compound"
    priority = 15
    blocks = []
    requires = {"context": ["timeline"]}
    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        # Exclude DaemonSets (handled elsewhere)
        owners = pod.get("metadata", {}).get("ownerReferences", [])
        if any(o.get("kind") == "DaemonSet" for o in owners):
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- REQUIRE a real scheduling failure signal ---
        recent_failed_scheduling = timeline.events_within_window(
            15, reason="FailedScheduling"
        )
        if not recent_failed_scheduling:
            return False

        # -------------------------------------------------
        # HARD EXCLUSION: temporal scheduling patterns
        # -------------------------------------------------
        # If repeated scheduling failures already indicate a timeout,
        # defer to SchedulingTimeoutExceeded (temporal rule).
        if len(recent_failed_scheduling) >= getattr(
            context.get("rule_config", {}).get("SchedulingTimeoutExceeded", {}),
            "min_repeats",
            3,
        ):
            return False

        # -------------------------------------------------
        # HARD EXCLUSION: specific scheduler failure signals
        # -------------------------------------------------
        SPECIFIC_MARKERS = (
            # Volume-related (your current failure)
            "volume node affinity conflict",
            # Topology-related
            "topology spread constraints",
            "didn't match pod's topology spread constraints",
            "missing required label",
            # Affinity / anti-affinity
            "node(s) didn't match pod affinity",
            "node(s) didn't match pod anti-affinity",
            # Node selector
            "node(s) didn't match node selector",
            # Taints / tolerations
            "had taint",
            "didn't tolerate",
            # Resource-specific (optional but recommended)
            "insufficient cpu",
            "insufficient memory",
            # Scheduler extender / plugin failures
            "error selecting node using extender",
            "scheduler extender",
            "failed to run extender",
            "extender",
            # HostPort allocation failures
            "didn't have free ports for the requested pod ports",
            "port is already allocated",
            "ports are already allocated",
            "port conflicts",
        )

        for e in recent_failed_scheduling:
            msg = (e.get("message") or "").lower()
            if any(marker in msg for marker in SPECIFIC_MARKERS):
                return False

        # -------------------------------------------------
        # Spec-level exclusions (still useful as fallback)
        # -------------------------------------------------
        spec = pod.get("spec", {})

        if spec.get("topologySpreadConstraints"):
            return False

        if spec.get("affinity"):
            return False

        if spec.get("nodeSelector"):
            return False

        if spec.get("tolerations"):
            return False

        # -------------------------------------------------
        # Node pressure fallback (true compound case)
        # -------------------------------------------------
        node_conditions = context.get("node_conditions", {})
        node_pressure = node_conditions.get(
            "DiskPressure", False
        ) or node_conditions.get("MemoryPressure", False)

        # PVC exclusion (correct)
        if context.get("blocking_pvc") is not None:
            return False

        # Final condition: ONLY generic unschedulable remains
        return node_pressure or bool(recent_failed_scheduling)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        # Determine specific scheduling constraint message
        node_conditions = context.get("node_conditions", {})
        constraint_details = []

        if node_conditions.get("DiskPressure"):
            constraint_details.append("DiskPressure=True")

        if node_conditions.get("MemoryPressure"):
            constraint_details.append("MemoryPressure=True")

        constraint_msg = "Unschedulable due to scheduling constraints"
        if constraint_details:
            constraint_msg += f" ({', '.join(constraint_details)})"

        causes_list = [
            Cause(
                code="SCHEDULING_CONSTRAINT",
                message=constraint_msg,
                role="scheduling_root",
                blocking=True,
            ),
            Cause(
                code="FAILED_SCHEDULING",
                message="Scheduler failed to place Pod on any available Node",
                role="scheduling_intermediate",
            ),
            Cause(
                code="POD_PENDING",
                message="Pod remains Pending due to unsatisfied scheduling constraints",
                role="workload_symptom",
            ),
        ]

        chain = CausalChain(causes=causes_list)

        root_cause_message = "Pod Pending due to unschedulable conditions"
        for cause in causes_list:
            if cause.code == "FAILED_SCHEDULING":
                root_cause_message += f" ({cause.code})"
                break

        object_evidence = {f"pod:{pod_name}, phase:Pending": ["Unschedulable"]}
        if node_conditions.get("DiskPressure") or node_conditions.get("MemoryPressure"):
            node_signals = []
            if node_conditions.get("DiskPressure"):
                node_signals.append("DiskPressure=True")
            if node_conditions.get("MemoryPressure"):
                node_signals.append("MemoryPressure=True")

            object_evidence["node:all_nodes"] = node_signals

        return {
            "root_cause": root_cause_message,
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} remains Pending",
                "FailedScheduling or node pressure events observed",
            ],
            "object_evidence": object_evidence,
            "likely_causes": [
                "Node taints",
                "Insufficient resources",
                "Disk or Memory pressure on nodes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "Check resource requests, taints, and node pressure",
            ],
            "blocking": True,
        }
