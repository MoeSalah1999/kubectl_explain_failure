from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ImageRegistryTLSFailureRule(FailureRule):
    """
    Detect image pull failures caused by TLS trust, certificate validation,
    or HTTPS negotiation problems when contacting image registries.

    Real-world behavior:
    - private and enterprise registries commonly use internally signed CAs
    - nodes frequently miss the required corporate root CA bundle
    - expired or rotated registry certificates break image pulls cluster-wide
    - container runtimes surface these failures as x509 / TLS verification
      errors during image resolution or layer download
    - this is operationally distinct from generic registry outages because
      transport connectivity usually works, but trust validation fails
    """

    name = "ImageRegistryTLSFailure"
    category = "Compound"
    priority = 91
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
    MIN_TLS_FAILURE_OCCURRENCES = 1

    PULL_REASONS = {
        "Failed",
        "FailedPull",
        "ErrImagePull",
        "BackOff",
        "ImagePullBackOff",
        "InspectFailed",
    }

    TLS_FAILURE_MARKERS = (
        # canonical x509 failures
        "x509:",
        "certificate signed by unknown authority",
        "unknown authority",
        "certificate has expired",
        "certificate is not yet valid",
        "cannot validate certificate",
        # hostname / SAN mismatch
        "certificate is valid for",
        "not ",
        "doesn't contain any ip sans",
        "tls: failed to verify certificate",
        # handshake / negotiation
        "tls handshake timeout",
        "remote error: tls",
        "tls: handshake failure",
        "tls: bad certificate",
        "tls: oversized record",
        "first record does not look like a tls handshake",
        # OCI runtime wording
        "failed to do request",
        "server gave http response to https client",
        "https client",
        "crypto/rsa: verification error",
    )

    # explicitly exclude non-TLS image pull causes
    EXCLUDED_MARKERS = (
        "unauthorized",
        "authentication required",
        "access denied",
        "manifest unknown",
        "not found",
        "name unknown",
        "toomanyrequests",
        "rate limit exceeded",
        "connection refused",
        "no such host",
        "i/o timeout",
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

    def _is_tls_pull_failure(self, event: dict[str, Any]) -> bool:
        reason = self._event_reason(event)
        if reason not in self.PULL_REASONS:
            return False

        message = self._event_message(event).lower()

        if not (
            "pull" in message
            or "image" in message
            or "https" in message
            or "tls" in message
            or "x509" in message
        ):
            return False

        if any(marker in message for marker in self.EXCLUDED_MARKERS):
            return False

        return any(marker in message for marker in self.TLS_FAILURE_MARKERS)

    def _extract_image(self, text: str) -> str | None:
        match = self.IMAGE_RE.search(text)
        if not match:
            return None
        return str(match.group("image"))

    def _extract_registry(
        self,
        image: str | None,
        text: str,
    ) -> str | None:
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

        matching_events = [
            event for event in ordered if self._is_tls_pull_failure(event)
        ]

        if not matching_events:
            return None

        total_occurrences = sum(self._occurrences(event) for event in matching_events)

        if total_occurrences < self.MIN_TLS_FAILURE_OCCURRENCES:
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
            "occurrences": total_occurrences,
            "dominant_message": message,
            "image": image or "<unknown-image>",
            "registry": registry,
            "container_name": container_name or "<unknown>",
            "waiting_reason": waiting_reason or "ImagePullBackOff",
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("ImageRegistryTLSFailure requires Timeline context")

        candidate = self._best_candidate(pod, timeline)
        if candidate is None:
            raise ValueError("ImageRegistryTLSFailure explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        image = candidate["image"]
        registry = candidate["registry"]
        container_name = candidate["container_name"]

        confidence = 0.96

        lowered = candidate["dominant_message"].lower()

        if "unknown authority" in lowered:
            confidence += 0.02

        if "certificate has expired" in lowered:
            confidence += 0.02

        chain = CausalChain(
            causes=[
                Cause(
                    code="IMAGE_PULL_REQUIRES_TLS_TRUST",
                    message=(
                        f"Container image '{image}' is pulled from TLS-protected registry '{registry}'"
                    ),
                    role="supply_chain_context",
                ),
                Cause(
                    code="REGISTRY_CERTIFICATE_VALIDATION_FAILED",
                    message=(
                        f"Node/container runtime cannot establish trusted TLS communication with registry '{registry}'"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="IMAGE_PULL_TLS_NEGOTIATION_ABORTED",
                    message=(
                        "Container runtime aborts image download because registry certificate validation or TLS negotiation fails"
                    ),
                    role="runtime_intermediate",
                ),
                Cause(
                    code="CONTAINER_IMAGE_CANNOT_BE_RETRIEVED",
                    message=(
                        "The workload remains blocked because kubelet cannot securely pull the required image"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (
                f"Observed {candidate['occurrences']} TLS-related image pull failure occurrence(s)"
            ),
            (
                f"Container '{container_name}' is currently waiting with reason "
                f"'{candidate['waiting_reason']}'"
            ),
            (
                f"Image pull attempts against registry '{registry}' fail with TLS/x509 validation errors"
            ),
            (
                "Failure signatures indicate certificate trust or TLS negotiation problems rather than generic connectivity or authentication failures"
            ),
        ]

        object_evidence = {
            f"pod:{pod_name}": [
                (
                    f"Pod startup is blocked because image '{image}' cannot be securely retrieved"
                ),
            ],
            f"container:{container_name}": [
                candidate["dominant_message"],
            ],
        }

        return {
            "root_cause": (
                f"TLS trust or certificate validation failure prevents pulling image '{image}' from registry '{registry}'"
            ),
            "confidence": min(confidence, 0.99),
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Corporate or internal registry CA is missing from node trust store",
                "Registry TLS certificate expired or rotated incorrectly",
                "Registry certificate hostname/SAN does not match registry endpoint",
                "HTTPS registry endpoint is misconfigured or serving invalid certificates",
                "Container runtime trust configuration differs across cluster nodes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                (
                    "kubectl get events --sort-by=.lastTimestamp "
                    "| grep -Ei 'x509|tls|certificate|pull'"
                ),
                (
                    f"openssl s_client -connect {registry.split(':')[0]}:443 "
                    "-showcerts"
                ),
                (f"crictl pull {image}"),
                (
                    "Verify the registry CA certificate exists under "
                    "/etc/containerd/certs.d or the node OS trust store"
                ),
                ("Restart containerd/cri-o after updating node trust bundles"),
            ],
        }
