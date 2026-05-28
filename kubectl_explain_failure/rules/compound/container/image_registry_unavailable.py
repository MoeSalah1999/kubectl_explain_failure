from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ImageRegistryUnavailableRule(FailureRule):
    """
    Detect image pull failures caused by registry-side unavailability,
    DNS resolution problems, transport failures, or upstream outages.

    Real-world behavior:
    - kubelet/containerd repeatedly retries image pulls when registries are
      unavailable or unreachable
    - these failures are operational transport failures, not authentication or
      image existence problems
    - transient registry outages often affect multiple workloads at once and
      present as ImagePullBackOff / ErrImagePull with network-oriented errors
    - common causes include DNS outages, TLS handshake failures, registry CDN
      incidents, upstream timeouts, or corporate proxy/network interception
    """

    name = "ImageRegistryUnavailable"
    category = "Container / Supply Chain"
    priority = 84
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ImagePullBackOff",
        "ErrImagePull",
    ]

    WINDOW_MINUTES = 30
    MIN_FAILURE_EVENTS = 2

    PULL_REASONS = {
        "Failed",
        "FailedPull",
        "ErrImagePull",
        "BackOff",
        "ImagePullBackOff",
        "InspectFailed",
    }

    # transport / availability indicators
    REGISTRY_UNAVAILABLE_MARKERS = (
        # DNS
        "no such host",
        "server misbehaving",
        "temporary failure in name resolution",
        "lookup ",
        "dial tcp: lookup",
        # TCP / routing
        "connection refused",
        "connect: connection refused",
        "network is unreachable",
        "no route to host",
        "connection reset by peer",
        # timeout / upstream
        "i/o timeout",
        "context deadline exceeded",
        "client.timeout exceeded",
        "tls handshake timeout",
        "request canceled while waiting for connection",
        "unexpected eof",
        # TLS / transport
        "tls: handshake failure",
        "remote error: tls",
        "x509:",
        "http2: server sent goaway",
        # registry availability
        "503 service unavailable",
        "502 bad gateway",
        "504 gateway timeout",
        "too many requests from registry upstream",
        "registry unavailable",
        "service unavailable",
        # OCI / container runtime transport
        "failed to do request",
        "failed to fetch anonymous token",
        "error pinging docker registry",
        "failed to resolve reference",
        "failed to authorize",
        "read: connection reset",
    )

    # explicitly excluded because they are separate root causes
    EXCLUDED_MARKERS = (
        "pull access denied",
        "requested access to the resource is denied",
        "authentication required",
        "unauthorized",
        "denied:",
        "incorrect username or password",
        "manifest unknown",
        "not found",
        "repository does not exist",
        "name unknown",
        "insufficient_scope",
        "quota exceeded",
        "rate limit exceeded",
        "toomanyrequests",
    )

    IMAGE_RE = re.compile(
        r"(?P<image>"
        r"(?:[a-z0-9.-]+(?::\d+)?/)?"
        r"[a-z0-9._/-]+"
        r"(?::[\w.-]+)?"
        r"(?:@sha256:[a-f0-9]{64})?"
        r")",
        re.IGNORECASE,
    )

    REGISTRY_RE = re.compile(
        r"(?P<registry>" r"(?:[a-z0-9-]+\.)+[a-z]{2,}" r"(?::\d+)?" r")",
        re.IGNORECASE,
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_timestamp(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_timestamp(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", ""))

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", ""))

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            return max(1, int(raw_count))
        except Exception:
            return 1

    def _container_waiting_reason(
        self,
        pod: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        statuses = pod.get("status", {}).get("containerStatuses", []) or []

        for status in statuses:
            state = status.get("state", {}) or {}
            waiting = state.get("waiting")
            if not isinstance(waiting, dict):
                continue

            reason = str(waiting.get("reason", ""))
            if reason in {"ImagePullBackOff", "ErrImagePull"}:
                return (
                    str(status.get("name", "<unknown>")),
                    reason,
                )

        return None, None

    def _is_pull_failure_event(self, event: dict[str, Any]) -> bool:
        reason = self._event_reason(event)
        if reason not in self.PULL_REASONS:
            return False

        message = self._event_message(event).lower()

        if not (
            "pull" in message
            or "image" in message
            or "registry" in message
            or "failed to resolve reference" in message
        ):
            return False

        if any(marker in message for marker in self.EXCLUDED_MARKERS):
            return False

        return any(marker in message for marker in self.REGISTRY_UNAVAILABLE_MARKERS)

    def _extract_image(self, text: str) -> str | None:
        match = self.IMAGE_RE.search(text)
        if not match:
            return None
        return str(match.group("image"))

    def _extract_registry(self, image: str | None, text: str) -> str | None:
        if image and "/" in image:
            first = image.split("/")[0]
            if "." in first or ":" in first:
                return first.lower()

        match = self.REGISTRY_RE.search(text)
        if match:
            return str(match.group("registry")).lower()

        return "docker.io"

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        matching_events: list[dict[str, Any]] = []

        for event in ordered:
            if self._is_pull_failure_event(event):
                matching_events.append(event)

        if not matching_events:
            return None

        total_occurrences = sum(self._occurrences(event) for event in matching_events)

        if total_occurrences < self.MIN_FAILURE_EVENTS:
            return None

        dominant_event = max(
            matching_events,
            key=self._occurrences,
        )

        message = self._event_message(dominant_event)
        image = self._extract_image(message)

        if image is None:
            for container in pod.get("spec", {}).get("containers", []) or []:
                image_value = container.get("image")
                if isinstance(image_value, str) and image_value:
                    image = image_value
                    break

        registry = self._extract_registry(image, message)

        container_name, waiting_reason = self._container_waiting_reason(pod)

        return {
            "events": matching_events,
            "dominant_message": message,
            "image": image or "<unknown-image>",
            "registry": registry,
            "container_name": container_name or "<unknown>",
            "waiting_reason": waiting_reason or "ImagePullBackOff",
            "occurrences": total_occurrences,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ImageRegistryUnavailable requires Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("ImageRegistryUnavailable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        image = candidate["image"]
        registry = candidate["registry"]
        container_name = candidate["container_name"]

        confidence = 0.95

        lowered = candidate["dominant_message"].lower()

        # stronger confidence for hard infrastructure failures
        if (
            "no such host" in lowered
            or "503" in lowered
            or "tls handshake timeout" in lowered
        ):
            confidence += 0.02

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_DEPENDS_ON_REMOTE_REGISTRY",
                    message=(
                        f"Container image '{image}' must be fetched from registry '{registry}' before startup"
                    ),
                    role="supply_chain_context",
                ),
                Cause(
                    code="REGISTRY_OR_TRANSPORT_UNAVAILABLE",
                    message=(
                        f"Registry '{registry}' is unreachable or unavailable due to DNS, network, TLS, or upstream transport failure"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_IMAGE_PULL_RETRIES_FAIL",
                    message=(
                        "Kubelet repeatedly retries image download but cannot establish a successful registry transfer"
                    ),
                    role="runtime_intermediate",
                ),
                Cause(
                    code="CONTAINER_NEVER_STARTS",
                    message=(
                        "The workload remains blocked in image pull failure state because the container image cannot be retrieved"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Observed {candidate['occurrences']} registry/image pull failure event occurrence(s) "
                f"within the recent incident window"
            ),
            (
                f"Container '{container_name}' is currently waiting with reason "
                f"'{candidate['waiting_reason']}'"
            ),
            (
                f"Image pull failures reference registry '{registry}' and contain "
                "transport or availability failure indicators"
            ),
            (
                "Failure signatures match operational registry unavailability rather "
                "than authentication, authorization, or missing-image conditions"
            ),
        ]

        object_evidence = {
            f"pod:{pod_name}": [
                (
                    f"Pod cannot start because image '{image}' cannot be pulled "
                    f"from registry '{registry}'"
                ),
            ],
            f"container:{container_name}": [
                candidate["dominant_message"],
            ],
        }

        return {
            "root_cause": (
                f"Container image registry '{registry}' is unavailable or unreachable, preventing image pull for '{image}'"
            ),
            "confidence": min(confidence, 0.99),
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Registry service outage or degraded upstream availability",
                "Cluster DNS failure preventing registry hostname resolution",
                "Corporate proxy, firewall, or egress network interruption",
                "TLS interception or certificate validation failure",
                "Registry CDN timeout or transient transport instability",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                (
                    "kubectl get events --sort-by=.lastTimestamp "
                    "| grep -i 'pull\\|image\\|registry'"
                ),
                (
                    f"kubectl run registry-test --rm -it "
                    f"--image={image} --restart=Never"
                ),
                (f"nslookup {registry.split(':')[0]}"),
                (f"crictl pull {image}"),
                "Check cluster egress connectivity, DNS, proxy, and registry provider status",
            ],
        }
