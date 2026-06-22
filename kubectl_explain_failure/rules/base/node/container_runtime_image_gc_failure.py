from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ContainerRuntimeImageGCFailureRule(FailureRule):
    """
    Detects node-level container runtime image garbage collection failures.
    """

    name = "ContainerRuntimeImageGCFailure"
    category = "Node"

    severity = "High"
    priority = 84

    phases = ["Pending", "Running"]

    container_states = ["waiting", "terminated", "running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["node", "pod"],
    }

    blocks = [
        "ImagePullBackOff",
        "ErrImagePull",
        "InvalidImageName",
        "ImagePullRateLimit",
    ]

    WINDOW_MINUTES = 30

    IMAGE_GC_REASONS = {"ImageGCFailed", "FreeDiskSpaceFailed"}

    IMAGE_GC_MARKERS = (
        "imagegcfailed",
        "failed to garbage collect",
        "image garbage collection failed",
        "failed to delete image",
        "imagefs",
        "garbage collect images",
        "freed 0 bytes",
        "no space left",
        "filesystem full",
    )

    DOWNSTREAM_PULL_MARKERS = (
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "back-off pulling image",
        "manifest unknown",
    )

    REGISTRY_FAILURE_MARKERS = (
        "unauthorized",
        "authentication required",
        "tls handshake",
        "i/o timeout",
        "connection refused",
        "lookup",
    )

    RECOVERY_REASONS = {"Started", "Pulled", "Created", "Ready"}

    # -------------------------
    # Helpers
    # -------------------------

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    # -------------------------
    # Classification
    # -------------------------

    def _is_runtime_gc_event(self, event: dict[str, Any]) -> bool:
        msg = self._message(event).lower()
        reason = self._reason(event).lower()

        # MUST explicitly be GC-related (tight scope)
        gc_reason_match = reason in {
            "imagegcfailed",
            "free disk space failed",
            "imagegc",
        }

        # MUST contain explicit GC intent (not generic filesystem/log errors)
        gc_marker_match = any(
            m in msg
            for m in (
                "image garbage collection",
                "garbage collect images",
                "image gc",
                "failed to garbage collect images",
            )
        )

        # HARD EXCLUSION: prevent overlap with storage/log rules
        exclusion_signals = (
            "overlayfs",
            "log write",
            "container log",
            "filesystem corruption",
            "write error",
            "permission denied",
            "io error",
        )

        if any(x in msg for x in exclusion_signals):
            return False

        return gc_reason_match or gc_marker_match

    def _is_registry_failure(self, event: dict[str, Any]) -> bool:
        msg = self._message(event).lower()
        return any(m in msg for m in self.REGISTRY_FAILURE_MARKERS)

    def _is_pull_failure(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        msg = self._message(event).lower()

        if not any(m in msg for m in self.DOWNSTREAM_PULL_MARKERS):
            return False

        inv = event.get("involvedObject", {})
        if isinstance(inv, dict):
            if inv.get("kind", "").lower() == "pod":
                return inv.get("name") == pod.get("metadata", {}).get("name")

        return True

    # -------------------------
    # Timeline
    # -------------------------

    def _ordered_recent_events(self, timeline: Timeline):
        events = timeline.events_within_window(self.WINDOW_MINUTES)
        return sorted(events, key=lambda e: self._event_time(e) or datetime.min)

    # -------------------------
    # GC collection
    # -------------------------

    def _collect_gc_events(self, events, pod):
        gc_events = []

        for e in events:
            if not self._is_runtime_gc_event(e):
                continue

            # HARD SCOPE: must be kubelet/runtime scoped only
            inv = e.get("involvedObject", {})
            if isinstance(inv, dict):
                kind = inv.get("kind", "").lower()

                # ONLY node/pod-level GC events allowed
                if kind not in ("node", "pod", ""):
                    continue

            gc_events.append(e)

        return gc_events

    def _is_gc_failure_signal(self, gc_events):
        return bool(gc_events)

    # -------------------------
    # Recovery guard
    # -------------------------

    def _recovered_after_gc_failure(self, timeline, gc_events):
        if not gc_events:
            return False

        last = self._event_time(gc_events[-1])
        if not last:
            return False

        for e in timeline.events:
            t = self._event_time(e)
            if t and t > last and self._reason(e) in self.RECOVERY_REASONS:
                return True
        return False

    # -------------------------
    # Candidate builder (FIXED)
    # -------------------------

    def _best_candidate(self, pod, timeline, context):
        events = self._ordered_recent_events(timeline)

        gc_events = self._collect_gc_events(events, pod)
        # ================================
        # HARD SCOPE FILTER (CRITICAL FIX)
        # Prevent overlap with other filesystem/storage rules
        # ================================

        message_blob = " ".join(self._message(e).lower() for e in gc_events[-5:])

        # If this looks like overlayfs / log-write / generic storage issue,
        # DO NOT let GC rule own it (prevents dilution)
        storage_overlap_signals = [
            "overlayfs",
            "log write",
            "failed to write log",
            "container log",
            "filesystem corruption",
        ]

        if any(sig in message_blob for sig in storage_overlap_signals):
            return None
        if not gc_events:
            return None

        if not self._is_gc_failure_signal(gc_events):
            return None

        if self._recovered_after_gc_failure(timeline, gc_events):
            return None

        pull_failures = [e for e in events if self._is_pull_failure(e, pod)]

        registry_failures = [e for e in events if self._is_registry_failure(e)]

        # suppression: registry dominates
        if registry_failures and len(registry_failures) > len(gc_events) * 2:
            return None

        return {
            "gc_events": gc_events,
            "pull_failures": pull_failures,
            "registry_failures": registry_failures,
            "gc_occurrences": sum(self._occurrences(e) for e in gc_events),
            "pull_occurrences": sum(self._occurrences(e) for e in pull_failures),
            "representative_gc_message": self._message(gc_events[-1]),
            "representative_pull_message": (
                self._message(pull_failures[-1]) if pull_failures else ""
            ),
        }

    # -------------------------
    # Matcher
    # -------------------------

    def matches(self, pod, events, context) -> bool:
        t = context.get("timeline")
        return isinstance(t, Timeline) and self._best_candidate(pod, t, context)

    # -------------------------
    # Causal chain
    # -------------------------

    def _build_causal_chain(self, candidate):
        return CausalChain(
            [
                Cause("NODE_IMAGEFS_EXHAUSTED", "Node image filesystem exhausted"),
                Cause(
                    "IMAGE_GC_FAILED",
                    "Container runtime GC cannot reclaim space",
                    blocking=True,
                ),
                Cause("IMAGEFS_FULL", "Filesystem remains full after GC attempts"),
            ]
        )

    # -------------------------
    # Confidence
    # -------------------------

    def _compute_confidence(self, candidate):
        c = 0.75

        if candidate["gc_occurrences"] > 2:
            c += 0.1
        if candidate["pull_occurrences"] > 0:
            c += 0.05

        return min(0.95, max(0.0, c))

    # -------------------------
    # Explain (SINGLE CLEAN VERSION)
    # -------------------------

    def explain(self, pod, events, context):
        timeline = context["timeline"]

        candidate = self._best_candidate(pod, timeline, context)
        if not candidate:
            raise ValueError("No GC failure detected")

        chain = self._build_causal_chain(candidate)
        confidence = self._compute_confidence(candidate)

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        ns = pod.get("metadata", {}).get("namespace", "default")

        return {
            "rule": self.name,
            "root_cause": "Container runtime image GC failure due to exhausted image filesystem",
            "confidence": confidence,
            "blocking": True,
            "causes": [c.__dict__ for c in chain.causes],
            "evidence": [
                f"{ns}/{pod_name} affected by image GC failure",
                candidate["representative_gc_message"],
                f"GC events: {candidate['gc_occurrences']}",
            ],
            "likely_causes": [
                "Image filesystem full",
                "kubelet GC thresholds misconfigured",
                "containerd snapshotter failure",
            ],
        }
