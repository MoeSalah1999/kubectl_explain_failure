from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeFragmentationPreventsPreemptionRule(FailureRule):
    """
    Detects scheduling failure caused by node-level resource fragmentation
    where:

    - Aggregate cluster capacity exists
    - But no single node can satisfy the Pod's resource request
    - Preemption is attempted but ineffective because resources are fragmented
    - Scheduler repeatedly fails with "insufficient" despite preemption attempts

    Real-world interpretation:
    - CPU/memory available but split across nodes
    - Pods cannot be packed due to bin-packing constraints
    - Preemption cannot consolidate resources onto a single node
    - Common in:
        - heterogeneous workloads
        - over-fragmented clusters
        - large resource requests (e.g. GPUs, high memory Pods)

    Signals:
    - Repeated FailedScheduling events
    - Messages contain BOTH:
        - insufficiency signals ("insufficient cpu/memory")
        - preemption signals ("preempt")
    - Sustained duration (not transient)
    - No Scheduled event
    - No dominant single-node failure (fragmentation pattern)

    Scope:
    - Scheduler behavior (bin-packing failure)
    - Compound rule (system-level placement failure)
    - Blocking (Pod cannot be scheduled)

    Exclusions:
    - Pure resource exhaustion (handled by InsufficientResources)
    - Preemption loops without fragmentation signal
    """

    name = "NodeFragmentationPreventsPreemption"
    category = "Compound"
    priority = 87  # slightly above preemption loop
    blocks = [
        "InsufficientResources",
        "PodUnschedulable",
        "SchedulerPreemptionLoop",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. High-frequency FailedScheduling ---
        recent = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent) < 5:
            return False

        # --- 2. Extract scheduler message signals ---
        insufficient_signals = 0
        preemption_signals = 0
        multi_node_pattern = 0

        for e in recent:
            msg = (e.get("message") or "").lower()

            # Resource insufficiency signals
            if "insufficient" in msg:
                insufficient_signals += 1

            # Preemption signals
            if "preempt" in msg:
                preemption_signals += 1

            # Multi-node / fragmentation hints (real scheduler wording)
            if "nodes are available" in msg or "0/" in msg:
                multi_node_pattern += 1

        # Must have both insufficiency AND preemption → fragmentation scenario
        if insufficient_signals < 3:
            return False

        if preemption_signals < 2:
            return False

        # Fragmentation hint (scheduler evaluated multiple nodes)
        if multi_node_pattern < 3:
            return False

        # --- 3. Sustained scheduling failure ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedScheduling"
        )

        if duration < 60:
            return False

        # --- 4. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # --- Extract dominant scheduler message ---
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(5, reason="FailedScheduling")
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_RESOURCE_FRAGMENTATION",
                    message="Cluster resources are fragmented across nodes",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="INSUFFICIENT_CONTIGUOUS_RESOURCES",
                    message="No single node has sufficient contiguous resources for the Pod",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="PREEMPTION_INEFFECTIVE",
                    message="Preemption cannot consolidate fragmented resources",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_BINPACKING_FAILURE",
                    message="Scheduler cannot place Pod due to bin-packing constraints",
                    role="control_loop",
                ),
            ]
        )

        return {
            "root_cause": "Pod cannot be scheduled due to node resource fragmentation preventing effective preemption",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events within short time window",
                "Scheduler reports insufficient resources across multiple nodes",
                "Preemption attempts observed but ineffective",
                "Sustained scheduling failure duration (>60s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Cluster resources fragmented across nodes",
                "Pod resource requests too large for any single node",
                "Inefficient bin-packing due to workload distribution",
                "Mixed workload sizes causing allocation gaps",
                "Preemption unable to free contiguous capacity",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "kubectl top nodes",
                "Check per-node allocatable vs requested resources",
                "Evaluate Pod resource requests (cpu/memory/gpu)",
                "Inspect existing Pod distribution across nodes",
                "Consider cluster autoscaling or node resizing",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling due to fragmented node capacity"
                ]
            },
        }
