from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeExpansionFailedRule(FailureRule):
    """
    Detects explicit PVC expansion failures.

    Real-world behavior:
    - `ExternalExpanding` is a waiting signal, not a failure
    - `VolumeResizeFailed` and `FileSystemResizeFailed` are the high-signal
      failure reasons
    - `FileSystemResizePending` should be handled by the dedicated pending rule,
      not by this failure rule
    """

    name = "VolumeExpansionFailed"
    category = "Storage"
    priority = 75
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
        "optional_objects": ["storageclass"],
    }

    FAILURE_REASONS = {
        "VolumeResizeFailed",
        "FileSystemResizeFailed",
    }

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _referenced_or_all_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]

        return referenced or pvc_objects

    def _has_filesystem_resize_pending(self, pvc: dict) -> bool:
        conditions = pvc.get("status", {}).get("conditions", []) or []
        return any(
            condition.get("type") == "FileSystemResizePending"
            and condition.get("status") == "True"
            for condition in conditions
        )

    def _matching_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if event.get("reason") in self.FAILURE_REASONS
        ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        pvcs = self._referenced_or_all_pvcs(pod, context)
        if not pvcs:
            return False

        if not any(
            pvc.get("status", {}).get("phase") == "Bound" for pvc in pvcs.values()
        ):
            return False

        if any(self._has_filesystem_resize_pending(pvc) for pvc in pvcs.values()):
            return False

        matched_events = self._matching_events(timeline)
        if not matched_events:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: e.get("reason") in self.FAILURE_REASONS
        )

        if total_failures < 2 and duration < 90:
            return False

        if timeline.count(reason="FileSystemResizeSuccessful") > 0:
            return False
        if timeline.count(reason="VolumeResizeSuccessful") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        pvc_names = sorted(self._referenced_or_all_pvcs(pod, context)) or ["<unknown>"]
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        if matched_events:
            messages = [
                (event.get("message") or "")
                for event in matched_events
                for _ in range(self._occurrences(event))
            ]
            dominant_msg = max(set(messages), key=messages.count)

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
                    message="CSI resizer or kubelet repeatedly retries volume expansion",
                    role="control_loop",
                ),
                Cause(
                    code="PVC_CAPACITY_NOT_UPDATED",
                    message="Requested storage capacity was not applied to the volume",
                    role="volume_intermediate",
                ),
                Cause(
                    code="WORKLOAD_STORAGE_CONSTRAINT",
                    message="Workload may be constrained by unexpanded storage capacity",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PersistentVolumeClaim expansion is failing due to CSI or storage backend limitations",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                "Explicit volume expansion failure events were observed",
                "Expansion retries persisted over time",
                "No successful expansion completion was observed",
                *(
                    ["Dominant expansion error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver does not support volume expansion",
                "Storage backend quota or size limits were exceeded",
                "Filesystem resize failed on the node",
                "Volume cannot be expanded online for this driver or volume type",
            ],
            "suggested_checks": [
                *[f"kubectl describe pvc {pvc_name}" for pvc_name in pvc_names],
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get storageclass -o yaml",
                "Check CSI resizer and node plugin logs",
            ],
            "blocking": True,
            "object_evidence": {
                **{
                    f"pvc:{pvc_name}": [
                        "PVC expansion repeatedly failed and did not complete"
                    ]
                    for pvc_name in pvc_names
                },
                f"pod:{pod_name}": [
                    "Pod may be impacted by insufficient or unexpanded storage"
                ],
            },
        }
