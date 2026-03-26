from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeExpansionThenCrashLoopRule(FailureRule):
    """
    Detects Pods that enter a CrashLoopBackOff after a volume expansion fails.

    Signals:
    - PVCs were resized but remain in Pending/Resizing state
    - Subsequent Pod restarts with CrashLoopBackOff indicate the workload
      cannot start due to volume issues
    - Timeline shows FailedMount or VolumeAttach errors after PVC resize

    Interpretation:
    The Pod cannot start because its container requires a volume that failed
    to expand. Kubernetes retries the Pod, causing repeated CrashLoopBackOffs.

    Scope:
    - Volume and workload layer (PVC + Pod lifecycle)
    - Deterministic escalation when volume expansion fails and affects Pod stability

    Exclusions:
    - Ignore PVCs already successfully resized
    - Ignore transient volume provisioning delays
    """

    name = "VolumeExpansionThenCrashLoop"
    category = "Compound"
    priority = 95
    deterministic = True
    blocks = [
        "CrashLoopBackOff",
        "FailedMount",
        "VolumeAttachError",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    RESIZE_MARKERS = (
        "resizing pvc",
        "volume expansion",
        "cannot expand volume",
    )

    CRASH_LOOP_MARKERS = (
        "crashloopbackoff",
        "back-off restarting",
        "container failed to start",
    )

    EXCLUSION_MARKERS = (
        "already resized",
        "resize completed",
    )

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

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        referenced_pvcs = self._referenced_pvcs(pod, context)
        if not referenced_pvcs:
            return False

        # Identify PVs with failed expansion
        failed_resize = 0
        for pvc in referenced_pvcs.values():
            status_msg = str(pvc.get("status", {}).get("message", "")).lower()
            if any(marker in status_msg for marker in self.RESIZE_MARKERS):
                if not any(marker in status_msg for marker in self.EXCLUSION_MARKERS):
                    failed_resize += 1
        if failed_resize == 0:
            return False

        # Detect CrashLoopBackOff events in timeline
        crash_hits = 0
        for event in timeline.raw_events:
            message = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()
            if reason == "backoff" or any(
                marker in message for marker in self.CRASH_LOOP_MARKERS
            ):
                crash_hits += self._occurrences(event)
        if crash_hits < 2:
            return False

        # Ensure sufficient temporal correlation (resizing precedes crash loop)
        duration = timeline.duration_between(
            lambda event: any(
                marker in str(event.get("message", "")).lower()
                for marker in self.RESIZE_MARKERS + self.CRASH_LOOP_MARKERS
            )
        )
        if duration < 30:  # at least 30s of sustained failure
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        referenced_pvcs = self._referenced_pvcs(pod, context)
        pvc_names = sorted(referenced_pvcs.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_EXPANSION_FAILED",
                    message="PVC volume expansion failed or stalled",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_ATTACH_FAILED",
                    message="Pod cannot attach/mount the volume due to failed expansion",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_CRASHLOOP",
                    message="Pod repeatedly restarts because required volume cannot be mounted",
                    role="workload_symptom",
                ),
            ]
        )
        object_evidence = {
            f"pod:{pod_name}": [
                "Pod enters CrashLoopBackOff due to failed volume expansion"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = ["PVC failed to expand as requested"]

        return {
            "root_cause": "Pod enters CrashLoopBackOff due to failed PVC expansion",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Referenced PVCs show failed or stalled expansion",
                "Pod enters CrashLoopBackOff after PVC expansion attempt",
                "Sustained failure over timeline (>30s)",
            ],
            "likely_causes": [
                "PVC resize cannot complete due to insufficient storage class support or node constraints",
                "Volume expansion conflicts with existing PV topology or usage",
                "Pod restarts repeatedly because it cannot mount required volumes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Inspect StorageClass and volume expansion capabilities",
                "Check node capacity and PV topology constraints",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
