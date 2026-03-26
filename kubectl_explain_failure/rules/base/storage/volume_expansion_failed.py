from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeExpansionFailedRule(FailureRule):
    """
    Detects PersistentVolumeClaim (PVC) expansion failures where:

    - A resize request has been issued (PVC spec increased)
    - The CSI driver or controller fails to complete expansion
    - The system repeatedly retries expansion without success

    Real-world interpretation:
    This occurs when:
    - CSI driver does not support expansion
    - Underlying storage backend rejects resize (quota, limits)
    - Filesystem resize fails on node
    - Volume is in-use and cannot be expanded online (driver limitation)
    - Controller expansion succeeds but node expansion fails

    Signals:
    - Repeated VolumeResizeFailed / ExternalExpanding / Resizing failures
    - Sustained retry duration (controller or kubelet loop)
    - No successful resize completion signal

    Scope:
    - CSI / storage lifecycle (post-provisioning)
    - PVC expansion workflow (controller + node phases)
    - Blocking when Pod depends on expanded capacity

    Exclusions:
    - Single transient resize failure
    - PVC provisioning failures (handled by PVC rules)
    """

    name = "VolumeExpansionFailed"
    category = "Storage"
    priority = 75

    phases = ["Pending", "Running", "ContainerCreating"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        pvc_objects = context.get("objects", {}).get("pvc", {})
        if not pvc_objects:
            return False

        # --- 1. Detect expansion-related failure signals ---
        expansion_failure_reasons = [
            "VolumeResizeFailed",
            "ExternalExpanding",
            "FileSystemResizeFailed",
        ]

        recent_failures = []
        for reason in expansion_failure_reasons:
            recent_failures.extend(timeline.events_within_window(5, reason=reason))

        if len(recent_failures) < 3:
            return False

        # --- 2. Ensure volume-related failure context exists ---
        if not timeline.has(kind="Volume", phase="Failure"):
            return False

        # --- 3. Sustained retry duration (controller/node loop) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") in expansion_failure_reasons
        )

        if duration < 90:  # expansion is slower → allow longer threshold
            return False

        # --- 4. Ensure no successful expansion completion ---
        success_signals = [
            "FileSystemResizeSuccessful",
            "VolumeResizeSuccessful",
        ]

        for success in success_signals:
            if timeline.count(reason=success) > 0:
                return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        pvc_objects = context.get("objects", {}).get("pvc", {})
        pvc_name = next(iter(pvc_objects.keys()), "<unknown>")

        # Extract dominant failure message
        dominant_msg = None
        if timeline:
            msgs: list[str] = []
            for r in [
                "VolumeResizeFailed",
                "ExternalExpanding",
                "FileSystemResizeFailed",
            ]:
                msgs.extend(
                    (e.get("message") or "")
                    for e in timeline.events_within_window(5, reason=r)
                )

            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_EXPANSION_FAILED",
                    message="PersistentVolumeClaim expansion cannot be completed",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CSI_EXPANSION_RETRY_LOOP",
                    message="CSI controller or kubelet repeatedly retries volume expansion",
                    role="control_loop",
                ),
                Cause(
                    code="PVC_CAPACITY_NOT_UPDATED",
                    message="Requested storage capacity not applied to volume",
                    role="volume_intermediate",
                ),
                Cause(
                    code="WORKLOAD_STORAGE_CONSTRAINT",
                    message="Workload may be constrained by insufficient storage capacity",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PersistentVolumeClaim expansion is failing due to CSI or storage backend limitations",
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                "Repeated volume expansion failure events within short time window",
                "Sustained expansion retry duration (>90s)",
                "Volume-related failure signals detected",
                "No successful expansion completion observed",
                *(
                    ["Dominant expansion error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver does not support volume expansion",
                "Storage backend quota or size limits exceeded",
                "Filesystem resize failure on node",
                "Volume cannot be expanded while in use (driver limitation)",
                "Mismatch between requested and supported storage class capabilities",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get storageclass -o yaml",
                "Check CSI driver logs (controller + node)",
                "Verify allowVolumeExpansion is enabled on StorageClass",
                "Check underlying storage provider quotas and limits",
            ],
            "blocking": True,
            "object_evidence": {
                f"pvc:{pvc_name}": [
                    "PVC expansion repeatedly failed and did not complete"
                ],
                f"pod:{pod_name}": [
                    "Pod may be impacted by insufficient or unexpanded storage"
                ],
            },
        }
