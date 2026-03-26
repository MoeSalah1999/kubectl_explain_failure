from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class VolumeMountPermissionDeniedRule(FailureRule):
    """
    Detects kubelet volume mount/setup failures caused by filesystem or export
    permission denial on the node.
    """

    name = "VolumeMountPermissionDenied"
    category = "Storage"
    priority = 52
    deterministic = True
    phases = ["Pending", "Running"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "FailedMount",
        "PVCMountFailed",
    ]

    PERMISSION_MARKERS = (
        "permission denied",
        "operation not permitted",
        "access denied",
        "not permitted",
    )

    MOUNT_MARKERS = (
        "mountvolume",
        "mountvolume.setup failed",
        "mountvolume.setupat failed",
        "failedmount",
        "set up failed for volume",
        "unable to mount volumes",
        "setup failed for volume",
    )

    def _event_source(self, event: dict) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _referenced_pvc_names(self, pod: dict, context: dict) -> list[str]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = []

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced.append(claim_name)

        return referenced or list(pvc_objects.keys())

    def _is_permission_denied_mount_event(self, event: dict) -> bool:
        reason = str(event.get("reason", "")).lower()
        message = str(event.get("message", "")).lower()
        source = self._event_source(event)

        if not any(marker in message for marker in self.PERMISSION_MARKERS):
            return False

        if reason == "failedmount":
            return True

        if source == "kubelet" and any(
            marker in message for marker in self.MOUNT_MARKERS
        ):
            return True

        return False

    def _matching_events(
        self, timeline: Timeline | None, events: list[dict]
    ) -> list[dict]:
        raw_events = timeline.raw_events if isinstance(timeline, Timeline) else events
        return [
            event
            for event in raw_events
            if self._is_permission_denied_mount_event(event)
        ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return bool(self._matching_events(timeline, events))

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline, events)

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        node_name = pod.get("spec", {}).get("nodeName", "<unknown>")
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced_pvcs = self._referenced_pvc_names(pod, context)
        first_message = (
            str(matched_events[0].get("message", "")).strip() if matched_events else ""
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_MOUNT_ATTEMPTED",
                    message="Kubelet attempted to set up and mount a volume for the Pod",
                    role="volume_context",
                ),
                Cause(
                    code="VOLUME_MOUNT_PERMISSION_DENIED",
                    message="Node-side volume setup or mount failed with permission denied",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_STARTUP_BLOCKED_BY_VOLUME_PERMISSION",
                    message="Pod cannot complete volume setup and start normally",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": ["Kubelet reported volume mount permission denial"],
        }
        if node_name != "<unknown>":
            object_evidence[f"node:{node_name}"] = [
                "Volume setup or mount on the node failed with permission denied"
            ]
        for pvc_name in referenced_pvcs:
            pvc_bound = (
                pvc_objects.get(pvc_name, {}).get("status", {}).get("phase") == "Bound"
            )
            object_evidence[f"pvc:{pvc_name}"] = [
                (
                    "PVC is Bound but mount/setup was denied"
                    if pvc_bound
                    else "PVC referenced by mount permission denial"
                )
            ]
        if first_message:
            object_evidence[f"pod:{pod_name}"].append(first_message)

        evidence = [
            "FailedMount or MountVolume event contains permission denied",
        ]
        if node_name != "<unknown>":
            evidence.append(f"Pod is assigned to node {node_name}")
        for pvc_name in referenced_pvcs:
            if pvc_objects.get(pvc_name, {}).get("status", {}).get("phase") == "Bound":
                evidence.append(f"PVC {pvc_name} is Bound")

        return {
            "rule": self.name,
            "root_cause": "Volume mount failed due to permission denied on the node",
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "NFS export or backing filesystem denied the node mount operation",
                "Volume path ownership or mode on the node is incompatible with kubelet setup",
                "CSI driver mount target directory permissions are incorrect",
                "SELinux or node-side security policy blocked the mount or chmod/chown step",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Inspect kubelet logs on the node for mount permission errors",
                "Verify node-side mount path ownership, permissions, and security policy",
                "Check backing storage export permissions and fsGroup or securityContext settings",
            ],
        }
