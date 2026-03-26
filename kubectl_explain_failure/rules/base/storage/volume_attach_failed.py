from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeAttachFailedRule(FailureRule):
    """
    Detects persistent volume attachment failures where:

    - The attach/detach controller fails to attach a volume to a node
    - The Pod cannot proceed to mounting
    - Failures repeat over time (not transient)

    Real-world interpretation:
    This occurs when:
    - Cloud provider cannot attach the disk (quota, API failure, zone mismatch)
    - Volume is already attached to another node (multi-attach conflict)
    - Node is not ready / unreachable for attachment
    - AttachDetach controller is retrying without success

    Signals:
    - Repeated FailedAttachVolume events
    - Occurring within a time window (not a single transient failure)
    - Sustained duration (retry loop)
    - No successful attach signal

    Scope:
    - Storage / volume lifecycle (attach phase)
    - Node-level volume availability
    - Blocking failure (Pod cannot start)

    Exclusions:
    - Single attach failure (transient)
    - Mount failures (handled by FailedMount rules)
    """

    name = "VolumeAttachFailed"
    category = "Storage"
    priority = 80

    phases = ["Pending", "ContainerCreating"]

    requires = {
        "context": ["timeline"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # --- 1. Repeated attach failures in recent window ---
        recent_failures = timeline.events_within_window(
            5,
            reason="FailedAttachVolume",
        )

        if len(recent_failures) < 3:
            return False

        # --- 2. Ensure this is a volume-related failure (structured signal) ---
        if not timeline.has(kind="Volume", phase="Failure"):
            return False

        # --- 3. Sustained retry duration (avoid transient attach blips) ---
        duration = timeline.duration_between(
            lambda e: e.get("reason") == "FailedAttachVolume"
        )

        if duration < 60:  # less than 1 minute → transient
            return False

        # --- 4. No successful attach signal ---
        # Kubernetes emits "SuccessfulAttachVolume" on success
        if timeline.count(reason="SuccessfulAttachVolume") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")

        # Extract dominant failure message (useful for cloud/provider-specific hints)
        dominant_msg = None
        if timeline:
            msgs = [
                (e.get("message") or "")
                for e in timeline.events_within_window(
                    5,
                    reason="FailedAttachVolume",
                )
            ]
            if msgs:
                dominant_msg = max(set(msgs), key=msgs.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_ATTACH_FAILED",
                    message="Volume cannot be attached to the target node",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="ATTACH_CONTROLLER_RETRY",
                    message="AttachDetach controller repeatedly retries volume attachment",
                    role="control_loop",
                ),
                Cause(
                    code="VOLUME_UNAVAILABLE_ON_NODE",
                    message="Volume not available on node, preventing container startup",
                    role="volume_intermediate",
                ),
                Cause(
                    code="POD_BLOCKED_ON_VOLUME",
                    message="Pod cannot start because required volume is not attached",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Volume attachment to node is failing, blocking Pod startup",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                "Repeated FailedAttachVolume events within short time window",
                "Volume attach failures persisted for >60 seconds",
                "No successful volume attachment observed",
                *(["Dominant attach error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "Volume already attached to another node (multi-attach conflict)",
                "Cloud provider failed to attach disk (quota, API error, or timeout)",
                "Node is not reachable or not ready for volume attachment",
                "Zone or topology mismatch between node and volume",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl describe node <node-name>",
                "kubectl describe pvc",
                "kubectl get volumeattachments",
                "Check cloud provider disk attachment status",
                "Verify volume is not attached to another node",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod blocked waiting for volume attachment to complete"
                ]
            },
        }
