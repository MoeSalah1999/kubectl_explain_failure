from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import parse_time


class VolumeExpansionThenCrashLoopRule(FailureRule):
    """
    Detects a Pod entering CrashLoopBackOff after an active PVC expansion
    failure or incomplete resize state on a referenced volume.
    """

    name = "VolumeExpansionThenCrashLoop"
    category = "Compound"
    priority = 95
    deterministic = False
    blocks = [
        "CrashLoopBackOff",
        "VolumeExpansionFailed",
        "FailedMount",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    EXPANSION_FAILURE_REASONS = {
        "VolumeResizeFailed",
        "FileSystemResizeFailed",
    }

    STORAGE_CORRELATION_MARKERS = (
        "failedmount",
        "mountvolume",
        "filesystem resize failed",
        "no space left",
        "disk full",
    )

    def _referenced_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}
        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]
        return referenced

    def _extract_timestamp(self, event: dict):
        timestamp = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not timestamp:
            return None
        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _parse_capacity(self, value: str | None) -> int | None:
        if not value:
            return None

        units = {
            "Ki": 1024,
            "Mi": 1024**2,
            "Gi": 1024**3,
            "Ti": 1024**4,
            "Pi": 1024**5,
            "Ei": 1024**6,
            "K": 1000,
            "M": 1000**2,
            "G": 1000**3,
            "T": 1000**4,
            "P": 1000**5,
            "E": 1000**6,
        }

        for suffix, multiplier in units.items():
            if value.endswith(suffix):
                try:
                    return int(float(value[: -len(suffix)]) * multiplier)
                except ValueError:
                    return None

        try:
            return int(value)
        except ValueError:
            return None

    def _pvc_still_unexpanded(self, pvc: dict) -> bool:
        conditions = pvc.get("status", {}).get("conditions", []) or []
        if any(
            condition.get("type") == "FileSystemResizePending"
            and condition.get("status") == "True"
            for condition in conditions
        ):
            return True

        requested = (
            pvc.get("spec", {}).get("resources", {}).get("requests", {}).get("storage")
        )
        capacity = pvc.get("status", {}).get("capacity", {}).get("storage")

        requested_bytes = self._parse_capacity(requested)
        capacity_bytes = self._parse_capacity(capacity)
        if requested_bytes is None or capacity_bytes is None:
            return False

        return requested_bytes > capacity_bytes

    def _expansion_failure_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if event.get("reason") in self.EXPANSION_FAILURE_REASONS
        ]

    def _crashloop_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            reason = str(event.get("reason", "")).lower()
            message = str(event.get("message", "")).lower()
            if reason == "backoff" or "crashloopbackoff" in message:
                matches.append(event)
        return matches

    def _has_storage_correlation(self, timeline) -> bool:
        for event in timeline.raw_events:
            message = str(event.get("message", "")).lower()
            reason = str(event.get("reason", "")).lower()
            if any(marker in message for marker in self.STORAGE_CORRELATION_MARKERS):
                return True
            if reason == "failedmount":
                return True
        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        referenced_pvcs = self._referenced_pvcs(pod, context)
        if not referenced_pvcs:
            return False

        if not any(
            self._pvc_still_unexpanded(pvc)
            or pvc.get("status", {}).get("phase") == "Bound"
            for pvc in referenced_pvcs.values()
        ):
            return False

        expansion_events = self._expansion_failure_events(timeline)
        active_unexpanded = any(
            self._pvc_still_unexpanded(pvc) for pvc in referenced_pvcs.values()
        )
        if not expansion_events and not active_unexpanded:
            return False

        crash_events = self._crashloop_events(timeline)
        if not crash_events:
            return False

        crashloop_status = any(
            status.get("state", {}).get("waiting", {}).get("reason")
            == "CrashLoopBackOff"
            for status in pod.get("status", {}).get("containerStatuses", []) or []
        )
        if not crashloop_status and len(crash_events) < 2:
            return False

        if expansion_events:
            expansion_times = [
                timestamp
                for timestamp in (
                    self._extract_timestamp(event) for event in expansion_events
                )
                if timestamp is not None
            ]
            crash_times = [
                timestamp
                for timestamp in (
                    self._extract_timestamp(event) for event in crash_events
                )
                if timestamp is not None
            ]
            if (
                expansion_times
                and crash_times
                and min(crash_times) <= min(expansion_times)
            ):
                return False

        if not self._has_storage_correlation(timeline) and not active_unexpanded:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        pvc_names = sorted(self._referenced_pvcs(pod, context))

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_EXPANSION_FAILED",
                    message="PVC expansion failed or remains incomplete",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="STORAGE_STATE_REMAINS_INCONSISTENT",
                    message="Workload sees storage state that did not catch up to the requested expansion",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_CRASHLOOP",
                    message="Pod repeatedly restarts after the failed or incomplete expansion",
                    role="workload_symptom",
                ),
            ]
        )
        object_evidence = {
            f"pod:{pod_name}": [
                "Pod enters CrashLoopBackOff after volume expansion failed or remained incomplete"
            ]
        }
        for pvc_name in pvc_names:
            object_evidence[f"pvc:{pvc_name}"] = [
                "PVC has active expansion failure or unexpanded requested size"
            ]

        return {
            "root_cause": "Pod enters CrashLoopBackOff after PVC expansion failed or remained incomplete",
            "confidence": 0.9,
            "causes": chain,
            "evidence": [
                "Referenced PVC still shows failed or incomplete expansion state",
                "CrashLoopBackOff starts after the expansion problem is present",
                "Storage-related follow-up signals remain visible for the Pod",
            ],
            "likely_causes": [
                "PVC resize cannot complete due to driver or backend limitations",
                "Filesystem resize did not finish on the node",
                "Application restarts because it still sees insufficient or inconsistent storage state",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl logs <pod> --previous",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Check CSI resizer and kubelet logs",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
