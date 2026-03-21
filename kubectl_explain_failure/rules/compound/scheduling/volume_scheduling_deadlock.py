from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeSchedulingDeadlockRule(FailureRule):
    """
    Detects deadlock between scheduler and volume binding.

    Real-world behavior:
    - Pod uses PVC with delayed binding (WaitForFirstConsumer)
    - Scheduler requires volume topology to pick node
    - Volume binding requires node selection
    - Circular dependency → Pod remains Pending indefinitely

    Signals:
    - Repeated FailedScheduling events
    - Messages referencing volume binding / PVC / topology
    - Lack of successful scheduling
    - Sustained duration
    """

    name = "VolumeSchedulingDeadlock"
    category = "Compound"
    priority = 92
    blocks = [
        "PodUnschedulable",
        "InsufficientResources",
        "PersistentVolumeClaimPending",
        "VolumeBindingFailure",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Repeated FailedScheduling events ---
        recent_failures = timeline.events_within_window(5, reason="FailedScheduling")

        if len(recent_failures) < 4:
            return False

        # --- 2. Detect volume-related scheduling signals ---
        volume_signals = 0

        for e in recent_failures:
            msg = (e.get("message") or "").lower()

            if (
                "persistentvolumeclaim" in msg
                or "pvc" in msg
                or "volume" in msg
                or "binding" in msg
                or "waitforfirstconsumer" in msg
                or "no persistent volumes available" in msg
                or "node affinity" in msg
                or "topology" in msg
            ):
                volume_signals += 1

        if volume_signals < 2:
            return False

        # --- 3. Optional: detect binding-related events ---
        binding_events = timeline.count(reason="FailedBinding")

        # If binding events exist, strengthen signal
        if binding_events == 0:
            # fallback: require stronger scheduler signal
            if volume_signals < 3:
                return False

        # --- 4. Sustained duration (avoid transient scheduling delay) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in ("FailedScheduling", "FailedBinding")
        )

        if duration < 60:
            return False

        # --- 5. No successful scheduling ---
        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant scheduling message
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
                    code="VOLUME_BINDING_CONSTRAINT",
                    message="PersistentVolumeClaim requires topology-aware binding",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_VOLUME_DEPENDENCY",
                    message="Scheduler requires volume binding information to select node",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="CIRCULAR_DEPENDENCY",
                    message="Volume binding and scheduling depend on each other",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains unscheduled due to volume scheduling deadlock",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod is stuck due to circular dependency between scheduling and volume binding",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events detected",
                "Scheduler messages reference PVC / volume binding constraints",
                "Volume binding events absent or failing",
                "Sustained scheduling failure (>60s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "StorageClass uses WaitForFirstConsumer binding mode",
                "PersistentVolume node affinity restricts scheduling",
                "Topology constraints (zones/regions) mismatch",
                "No compatible PV available for requested PVC",
                "Cluster topology prevents simultaneous scheduling and binding",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc",
                "kubectl describe pvc",
                "kubectl get pv",
                "kubectl describe pv",
                "kubectl get storageclass -o yaml",
                "Check volumeBindingMode (WaitForFirstConsumer)",
                "Inspect PV nodeAffinity and topology constraints",
                "Verify nodes match PV topology requirements",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot be scheduled due to unresolved volume binding constraints"
                ]
            },
        }
