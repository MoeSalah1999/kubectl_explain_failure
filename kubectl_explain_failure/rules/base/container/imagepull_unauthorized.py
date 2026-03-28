from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ImagePullUnauthorizedRule(FailureRule):
    """
    Detects image pull failures caused by registry authentication or
    authorization rejection.

    Real-world behavior:
    - the first high-signal event is usually ErrImagePull, often followed by
      ImagePullBackOff as kubelet retries
    - registry auth failures include 401/403 style text, failed token fetches,
      denied pull scope, or explicit authentication-required responses
    - if the Pod already references concrete imagePullSecrets present in
      context, ImagePullSecretMissing remains the more specific explanation
    """

    name = "ImagePullUnauthorized"
    category = "Image"
    priority = 55
    deterministic = True

    phases = ["Pending"]
    container_states = ["waiting"]

    requires = {
        "context": ["timeline"],
        "optional_objects": ["secret"],
    }

    blocks = [
        "ImagePullError",
        "ImagePullBackOff",
    ]

    AUTH_MARKERS = (
        "unauthorized",
        "authentication required",
        "failed to authorize",
        "failed to fetch anonymous token",
        "no basic auth credentials",
        "requested access to the resource is denied",
        "access forbidden",
        "insufficient_scope",
        "401 unauthorized",
        "403 forbidden",
        "pull access denied",
        "denied:",
    )

    NON_AUTH_MARKERS = (
        "manifest unknown",
        "not found",
        "name unknown",
        "connection refused",
        "i/o timeout",
        "dial tcp",
        "tls handshake timeout",
        "context deadline exceeded",
        "no such host",
        "server misbehaving",
        "x509:",
    )

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_auth_message(self, message: str) -> bool:
        msg = (message or "").lower()
        if not msg:
            return False

        if any(marker in msg for marker in self.NON_AUTH_MARKERS):
            return False

        return any(marker in msg for marker in self.AUTH_MARKERS)

    def _matching_events(self, timeline) -> list[dict]:
        matches = []
        for event in timeline.raw_events:
            if event.get("reason") not in {"ErrImagePull", "ImagePullBackOff"}:
                continue

            if self._is_auth_message(str(event.get("message", ""))):
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

    def _pod_uses_resolved_pull_secret(self, pod: dict, context: dict) -> bool:
        secret_objects = context.get("objects", {}).get("secret", {})
        if not secret_objects:
            return False

        for secret_ref in pod.get("spec", {}).get("imagePullSecrets", []) or []:
            name = secret_ref.get("name")
            if name and name in secret_objects:
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Preserve precedence for the existing secret-specific rule.
        if self._pod_uses_resolved_pull_secret(pod, context):
            return False

        matched_events = self._matching_events(timeline)
        waiting_auth = any(
            self._is_auth_message(message)
            for message in self._waiting_state_messages(pod)
        )

        if not matched_events and not waiting_auth:
            return False

        total_failures = sum(self._occurrences(event) for event in matched_events)
        duration = timeline.duration_between(
            lambda e: e.get("reason") in {"ErrImagePull", "ImagePullBackOff"}
            and self._is_auth_message(str(e.get("message", "")))
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
                    code="PRIVATE_REGISTRY_ACCESS_REQUIRED",
                    message="Container image requires authenticated or authorized registry access",
                    role="workload_context",
                ),
                Cause(
                    code="REGISTRY_AUTHORIZATION_FAILED",
                    message="Registry rejected the image pull request as unauthorized",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_BLOCKED",
                    message="Kubelet cannot pull the image until registry access is fixed",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Registry rejected the image pull due to authentication or authorization failure",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "ErrImagePull or ImagePullBackOff includes explicit registry authorization failure markers",
                "Unauthorized image pull failures repeat or progress into backoff",
                *(["Dominant auth error: " + dominant_msg] if dominant_msg else []),
            ],
            "likely_causes": [
                "Pod or node has no valid credentials for the private registry",
                "Registry token or credential helper is expired or rejected",
                "Registry repository exists but the caller lacks pull permissions",
                "Workload identity or node identity is not authorized for this image repository",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Verify registry credentials or credential provider configuration",
                "Confirm the registry repository grants pull access to this workload or node identity",
                "Retry the image pull with the same credentials outside the cluster",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod cannot start because the registry denied access to the requested image"
                ]
            },
        }
