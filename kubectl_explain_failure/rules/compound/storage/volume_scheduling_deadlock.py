from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeSchedulingDeadlockRule(FailureRule):
    """
    Detects Pods that are stuck in a circular dependency between
    topology-aware volume scheduling and WaitForFirstConsumer
    PVC binding, preventing forward progress.

    Signals:
    - Pod remains in Pending phase
    - Referenced PVCs are Pending and use a StorageClass with
    volumeBindingMode set to WaitForFirstConsumer
    - Repeated FailedScheduling events indicate volumes cannot be
    bound for candidate nodes
    - Binding progress signals are observed but do not resolve
    - Duration of failure exceeds a sustained threshold (~60s)

    Interpretation:
    The Pod cannot be scheduled because its placement depends
    on volumes that cannot yet be bound, and those volumes
    cannot be bound because no node has been selected to
    consume them. This creates a deadlock between the scheduler
    and the volume binding subsystem. The repeated FailedScheduling
    events and stalled PVC binding indicate a deterministic,
    non-transient condition rather than a temporary delay.

    Scope:
    - Volume and scheduler layer (PVC binding + Pod placement)
    - Deterministic (object state + timeline duration)
    - Captures sustained, compound deadlocks in topology-aware
    scheduling for WaitForFirstConsumer volumes
    - Acts as a temporal escalation rule when PVCs block scheduling

    Exclusions:
    - Excludes volumes that are already bound or attached
    - Ignores transient provisioning delays
    - Ignores volume node affinity conflicts or multi-attach
    errors that are resolved by normal scheduler operations
    """

    name = "VolumeSchedulingDeadlock"
    category = "Compound"
    priority = 92
    deterministic = True
    blocks = [
        "PodUnschedulable",
        "InsufficientResources",
        "PVCNotBound",
        "VolumeBindingFailure",
        "StorageClassProvisionerMissing",
        "FailedScheduling",
    ]
    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc", "storageclass"],
    }

    SCHEDULING_MARKERS = (
        "didn't find available persistent volumes to bind",
        "did not find available persistent volumes to bind",
        "unbound immediate persistentvolumeclaims",
        "persistentvolumeclaim is not bound",
        "volume binding",
    )

    BINDING_PROGRESS_MARKERS = (
        "waiting for first consumer to be created before binding",
        "waitforfirstconsumer",
        "failedbinding",
        "no persistent volumes available",
    )

    EXCLUSION_MARKERS = (
        "volume node affinity conflict",
        "already attached",
        "multi-attach",
        "exclusively attached",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _referenced_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        objects = context.get("objects", {})
        pvc_objects = objects.get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]

        return referenced

    def _storageclass_uses_wait_for_first_consumer(
        self, pvc: dict, context: dict
    ) -> bool:
        storageclass_name = pvc.get("spec", {}).get("storageClassName")
        if not storageclass_name:
            return False

        storageclasses = context.get("objects", {}).get("storageclass", {})
        storageclass = storageclasses.get(storageclass_name)
        if not storageclass:
            return False

        return storageclass.get("volumeBindingMode") == "WaitForFirstConsumer"

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        referenced_pvcs = self._referenced_pvcs(pod, context)
        if not referenced_pvcs:
            return False

        pending_wffc_pvcs = {
            name: pvc
            for name, pvc in referenced_pvcs.items()
            if pvc.get("status", {}).get("phase") != "Bound"
            and self._storageclass_uses_wait_for_first_consumer(pvc, context)
        }
        if not pending_wffc_pvcs:
            return False

        recent_failures = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent_failures:
            return False

        scheduling_hits = 0
        total_failures = 0
        repeated_signal = False

        for event in recent_failures:
            message = str(event.get("message", "")).lower()
            occurrences = self._occurrences(event)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            if any(marker in message for marker in self.EXCLUSION_MARKERS):
                return False

            if any(marker in message for marker in self.SCHEDULING_MARKERS):
                scheduling_hits += occurrences

        if scheduling_hits < 2:
            return False
        if total_failures < 3:
            return False

        binding_progress_signals = 0
        for event in timeline.raw_events:
            message = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()
            if reason == "failedbinding" or any(
                marker in message for marker in self.BINDING_PROGRESS_MARKERS
            ):
                binding_progress_signals += self._occurrences(event)

        if binding_progress_signals < 1:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") in ("FailedScheduling", "FailedBinding")
            or "first consumer" in str(event.get("message", "")).lower()
        )
        if duration < 60 and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        referenced_pvcs = self._referenced_pvcs(pod, context)
        pvc_names = sorted(referenced_pvcs.keys())

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
                    code="WAIT_FOR_FIRST_CONSUMER_VOLUME_BINDING",
                    message="PVC requires WaitForFirstConsumer topology-aware binding",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_SCHEDULING_DEADLOCK",
                    message="Volume binding and scheduler placement cannot make forward progress together",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_VOLUME_BINDING_LOOP",
                    message="Scheduler repeatedly retries placement while PVC binding remains unresolved",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because topology-aware volume binding never resolves",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod cannot be scheduled because topology-aware volume binding is unresolved"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC remains Pending under a WaitForFirstConsumer StorageClass"
            ]

        return {
            "root_cause": "Pod is stuck due to circular dependency between scheduling and WaitForFirstConsumer volume binding",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Referenced PVCs remain Pending under WaitForFirstConsumer binding",
                "Scheduler messages indicate volumes could not be bound for scheduling",
                "PVC binding progress is stalled waiting for a consumer or compatible volume",
                "Sustained scheduling failure (>60s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "StorageClass uses WaitForFirstConsumer and no feasible node-volume pairing exists",
                "Available volumes cannot satisfy topology or capacity requirements for any candidate node",
                "PVC binding and pod placement are waiting on each other without progress",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "kubectl get storageclass -o yaml",
                "Check volumeBindingMode on the referenced StorageClass",
                "Inspect PV availability and topology constraints",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
