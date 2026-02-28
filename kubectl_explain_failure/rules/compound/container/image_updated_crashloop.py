from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImageUpdatedThenCrashLoopRule(FailureRule):
    """
    Detects Pods that enter CrashLoopBackOff shortly after a new container
    image has been deployed, indicating a runtime failure triggered by the
    image update.

    Signals:
    - Image pull or deployment event observed in pod timeline
    - Container enters CrashLoopBackOff following image update

    Interpretation:
    The newly deployed image caused the container to fail at runtime,
    leading to repeated restarts (CrashLoopBackOff). This prevents the
    Pod from reaching a stable running state.

    Scope:
    - Timeline + container runtime layer
    - Deterministic (event-based correlation)
    - Acts as a compound check for image-induced CrashLoops

    Exclusions:
    - Does not include CrashLoops caused by configuration changes
    - Does not include transient startup failures unrelated to image
    deployment
    """

    name = "ImageUpdatedThenCrashLoop"
    category = "Compound"
    priority = 61  # Higher than config-change chain
    blocks = [
        "CrashLoopBackOff",
        "ImagePullError",
        "InvalidEntrypoint",
    ]

    phases = ["Running", "CrashLoopBackOff"]

    requires = {
        "context": ["timeline"],
    }

    container_states = ["waiting", "terminated"]

    IMAGE_UPDATE_REASONS = {
        "Pulled",
        "Pulling",
        "SuccessfulCreate",
    }

    CRASH_REASONS = {
        "BackOff",
        "CrashLoopBackOff",
    }

    MAX_TIME_DELTA_SECONDS = 300  # 5 minute window

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        image_events = [
            e
            for e in timeline.raw_events
            if e.get("reason") in self.IMAGE_UPDATE_REASONS
        ]

        if not image_events:
            return False

        crash_events = [
            e for e in timeline.raw_events if e.get("reason") in self.CRASH_REASONS
        ]

        if not crash_events:
            return False

        duration = timeline.duration_between(
            lambda e: e.get("reason") in self.IMAGE_UPDATE_REASONS
            or e.get("reason") in self.CRASH_REASONS
        )

        if duration <= 0 or duration > self.MAX_TIME_DELTA_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        container_name = "<unknown>"
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            if any(k in state for k in ["waiting", "terminated"]):
                container_name = cs.get("name", "<unknown>")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_DEPLOYMENT_EVENT",
                    message="Timeline shows container image pull or update events",
                    role="image_context",
                ),
                Cause(
                    code="CONTAINER_RUNTIME_FAILURE",
                    message="Container runtime failure after image update",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CRASHLOOP",
                    message="Pod entered CrashLoopBackOff state",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoop triggered by recent image update",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                "Image pull event detected",
                "CrashLoopBackOff followed image update",
                f"Time delta <= {self.MAX_TIME_DELTA_SECONDS} seconds",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["CrashLoop began after new image deployment"],
                f"container:{container_name}": ["Container failed after image update"],
            },
            "suggested_checks": [
                "Verify image tag and digest",
                "Roll back to previous image",
                "Inspect container logs",
                "Validate entrypoint and environment variables",
            ],
            "blocking": True,
        }
