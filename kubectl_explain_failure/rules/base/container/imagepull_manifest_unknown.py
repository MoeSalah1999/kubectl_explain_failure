from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImagePullManifestUnknownRule(FailureRule):
    """
    Detects image pull failures where the registry cannot resolve the requested
    manifest or tag.

    Real-world behavior:
    - kubelet usually emits ErrImagePull first, then ImagePullBackOff as retries
      continue
    - common registry messages include `manifest unknown`, `manifest for <image>
      not found`, or `failed to resolve reference`
    - this should not match registry auth failures, transient network failures,
      or architecture mismatch errors
    """

    name = "ImagePullManifestUnknown"
    category = "Image"
    priority = 58
    deterministic = True

    phases = ["Pending"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
    }

    blocks = [
        "ImagePullError",
        "ImagePullBackOff",
    ]

    MANIFEST_MARKERS = (
        "manifest unknown",
        "manifest for ",
        "failed to resolve reference",
        "not found: manifest unknown",
    )

    EXCLUSION_MARKERS = (
        "unauthorized",
        "authentication required",
        "failed to authorize",
        "no basic auth credentials",
        "requested access to the resource is denied",
        "pull access denied",
        "401 unauthorized",
        "403 forbidden",
        "connection refused",
        "i/o timeout",
        "dial tcp",
        "tls handshake timeout",
        "context deadline exceeded",
        "no such host",
        "server misbehaving",
        "x509:",
        "no matching manifest for ",
        "exec format error",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_manifest_unknown_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.EXCLUSION_MARKERS):
            return False

        if "manifest for " in msg and " not found" in msg:
            return True

        return any(marker in msg for marker in self.MANIFEST_MARKERS)

    def _matching_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            if event.get("reason") not in {"ErrImagePull", "ImagePullBackOff"}:
                continue

            if self._is_manifest_unknown_message(str(event.get("message", ""))):
                matches.append(event)

        return matches

    def _waiting_state_messages(self, pod: dict) -> list[str]:
        messages = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            reason = waiting.get("reason")
            if reason in {"ErrImagePull", "ImagePullBackOff"}:
                message = waiting.get("message")
                if message:
                    messages.append(message)
        return messages

    def _has_backoff_state(self, pod: dict, timeline) -> bool:
        if timeline and timeline.count(reason="ImagePullBackOff") > 0:
            return True

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting") or {}
            if waiting.get("reason") == "ImagePullBackOff":
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        matched_events = self._matching_events(timeline)
        waiting_manifest = any(
            self._is_manifest_unknown_message(message)
            for message in self._waiting_state_messages(pod)
        )

        if not matched_events and not waiting_manifest:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: e.get("reason") in {"ErrImagePull", "ImagePullBackOff"}
            and self._is_manifest_unknown_message(str(e.get("message", "")))
        )

        if (
            total_failures < 2
            and duration < 30
            and not self._has_backoff_state(pod, timeline)
        ):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        matched_events = self._matching_events(timeline) if timeline else []

        dominant_msg = None
        messages = [
            (event.get("message") or "")
            for event in matched_events
            for _ in range(self._occurrences(event))
        ]
        if not messages:
            messages = self._waiting_state_messages(pod)
        if messages:
            dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_REFERENCE_REQUESTED",
                    message="Pod requests a specific image manifest or tag from the registry",
                    role="workload_context",
                ),
                Cause(
                    code="IMAGE_MANIFEST_NOT_FOUND",
                    message="Registry could not find the requested image manifest or tag",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_CANNOT_PROGRESS",
                    message="Kubelet cannot pull the image because the requested manifest is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Requested image manifest or tag does not exist in the registry",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "ErrImagePull or ImagePullBackOff includes explicit manifest-not-found markers",
                "Manifest lookup failures repeat or progress into backoff",
                *(["Dominant manifest error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "Image tag was mistyped or never pushed to the registry",
                "Deployment still references an old image digest or tag that was deleted",
                "Registry repository exists but the requested manifest was garbage-collected or never published",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Verify the image name, tag, or digest exists in the target registry",
                "Compare the deployed image reference with the tags or manifests published by CI",
                "Check whether the workload should pin a valid digest instead of a missing tag",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because the requested image manifest is missing from the registry"
                ]
            },
        }
