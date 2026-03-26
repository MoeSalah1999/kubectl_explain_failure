from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIPluginCrashLoopRule(FailureRule):
    """
    Detects Pods stuck in a CSI driver CrashLoopBackOff.

    Real-world interpretation:
    - CSI driver sidecar or plugin container repeatedly crashes
    - Persistent volumes managed by CSI remain unavailable
    - Pod operations depending on storage fail
    - Often caused by misconfigured drivers, incompatible Kubernetes versions, or storage endpoint issues
    """

    name = "CSIPluginCrashLoop"
    category = "Compound"
    priority = 90
    deterministic = True
    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "VolumeAttachError",
        "PVCNotBound",
        "FailedScheduling",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc", "storageclass"],
    }

    CRASH_MARKERS = (
        "csi plugin crashloop",
        "container failed",
        "back-off restarting",
        "terminated with exit code",
        "oomkilled",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _has_csi_crash_events(self, timeline) -> bool:
        recent_failures = timeline.events_within_window(15)
        for e in recent_failures:
            message = str(e.get("message", "")).lower()
            if any(marker in message for marker in self.CRASH_MARKERS):
                return True
        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not self._has_csi_crash_events(timeline):
            return False

        crash_count = sum(
            self._occurrences(e)
            for e in timeline.events_within_window(15)
            if any(
                marker in str(e.get("message", "")).lower()
                for marker in self.CRASH_MARKERS
            )
        )

        # Realistic threshold: multiple crashes in short window
        if crash_count < 2:
            return False

        # Ensure at least 60s of sustained crash events
        duration = timeline.duration_between(
            lambda event: any(
                marker in str(event.get("message", "")).lower()
                for marker in self.CRASH_MARKERS
            )
        )
        if duration < 60:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_PLUGIN_CRASH",
                    message="CSI driver/plugin container repeatedly crashes",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_UNAVAILABLE",
                    message="Persistent volumes managed by CSI remain unavailable",
                    role="volume_context",
                ),
                Cause(
                    code="POD_PENDING_OR_FAILING",
                    message="Pod fails operations dependent on CSI-managed storage",
                    role="workload_symptom",
                ),
                Cause(
                    code="CRASHLOOP_BACKOFF",
                    message="Kubernetes observes repeated back-off restarts",
                    role="control_loop",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod operations impacted by CSI plugin crash",
                "Container logs indicate repeated CSI plugin crashes",
            ]
        }

        return {
            "root_cause": "Pod affected by CSI driver/plugin CrashLoopBackOff",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "CSI plugin container shows repeated crash events",
                "Sustained back-off restarts (>60s)",
                "Dependent PVCs remain Pending or fail to attach",
            ],
            "likely_causes": [
                "CSI driver misconfiguration or version mismatch",
                "Storage endpoint or network issues affecting plugin",
                "Resource starvation causing container OOM or termination",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl logs <csi-plugin-pod> -c <csi-container>",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Inspect CSI driver Deployment or DaemonSet logs",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
