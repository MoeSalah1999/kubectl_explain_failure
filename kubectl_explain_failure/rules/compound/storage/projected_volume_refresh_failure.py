from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Callable

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ProjectedVolumeRefreshFailureRule(FailureRule):
    """
    Detects projected volume refresh failures for Secrets, ConfigMaps,
    ServiceAccount tokens, and CSI-backed projections.

    Real-world behavior:
    - kubelet continuously refreshes projected volumes in-place without
      restarting pods
    - failures usually surface after startup, while the pod is already Running
    - Secret/ConfigMap rotation may partially fail because kubelet cannot fetch
      updated objects, cannot write the projected payload atomically, or the
      CSI/provider layer cannot refresh material
    - serviceAccountToken projections fail during TokenRequest API errors,
      authentication outages, API server reachability problems, or kubelet
      authorization failures
    - pods often continue running with stale projected content while kubelet
      emits repeated MountVolume/atomic writer/projection refresh events
    """

    name = "ProjectedVolumeRefreshFailure"
    category = "Storage"
    priority = 76
    deterministic = True

    phases = ["Running", "Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "SecretNotFound",
        "ConfigMapNotFound",
        "FailedMount",
        "ServiceAccountTokenFailure",
        "CSISecretsStoreMountFailure",
        "StaleSecretMounted",
    ]

    WINDOW_MINUTES = 45
    MIN_FAILURE_EVENTS = 2
    MIN_FAILURE_DURATION_SECONDS = 300.0

    CACHE_KEY = "_projected_volume_refresh_failure"

    PROJECTION_RELATED_REASONS = {
        "failedmount",
        "mountvolume.setupsucceeded",
        "mountvolume.setupfailed",
        "failed",
    }

    REFRESH_FAILURE_MARKERS = (
        "projected",
        "projection",
        "atomic writer",
        "failed to sync secret cache",
        "failed to sync configmap cache",
        "failed to fetch token",
        "tokenrequest",
        "serviceaccount token",
        "couldn't get secret",
        "couldn't get configmap",
        "object not registered",
        "timed out waiting for the condition",
        "unable to fetch",
        "failed to fetch",
        "failed to refresh",
        "failed to sync",
        "error processing secret",
        "error processing configmap",
        "volume mount failed",
        "failed to write payload",
        "write payload",
        "no such host",
        "connection refused",
        "tls handshake timeout",
        "i/o timeout",
        "context deadline exceeded",
        "secrets-store.csi.k8s.io",
        "failed to mount secrets store objects",
        "rpc error",
    )

    STALE_CONTENT_MARKERS = (
        "using stale",
        "stale content",
        "stale secret",
        "stale configmap",
        "unable to update",
        "will retry",
        "retrying",
    )

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

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "")
        return str(source or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _pod_key(self, pod: dict[str, Any]) -> tuple[str, str]:
        metadata = pod.get("metadata", {}) or {}
        return (
            str(metadata.get("namespace") or "default"),
            str(metadata.get("name") or ""),
        )

    def _event_involves_pod(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        involved = event.get("involvedObject")
        if not isinstance(involved, dict):
            return False

        namespace, pod_name = self._pod_key(pod)

        kind = str(involved.get("kind") or "").lower()
        if kind and kind != "pod":
            return False

        if involved.get("name") and involved.get("name") != pod_name:
            return False

        if (
            involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False

        return True

    def _collect_projection_targets(
        self,
        pod: dict[str, Any],
    ) -> dict[str, list[str]]:
        targets: dict[str, list[str]] = {}

        def add(target: str, description: str) -> None:
            targets.setdefault(target, [])
            if description not in targets[target]:
                targets[target].append(description)

        spec = pod.get("spec", {}) or {}

        for volume in spec.get("volumes", []) or []:
            volume_name = str(volume.get("name") or "<volume>")

            projected = volume.get("projected")
            if not isinstance(projected, dict):
                continue

            for source in projected.get("sources", []) or []:
                if not isinstance(source, dict):
                    continue

                secret = source.get("secret")
                if isinstance(secret, dict) and secret.get("name"):
                    add(
                        f"secret:{secret['name']}",
                        f"Projected Secret in volume '{volume_name}'",
                    )

                configmap = source.get("configMap")
                if isinstance(configmap, dict) and configmap.get("name"):
                    add(
                        f"configmap:{configmap['name']}",
                        f"Projected ConfigMap in volume '{volume_name}'",
                    )

                if "serviceAccountToken" in source:
                    add(
                        "serviceaccounttoken",
                        f"Projected serviceAccountToken in volume '{volume_name}'",
                    )

                cluster_trust_bundle = source.get("clusterTrustBundle")
                if cluster_trust_bundle:
                    add(
                        "clustertrustbundle",
                        f"Projected ClusterTrustBundle in volume '{volume_name}'",
                    )

            csi = volume.get("csi") or {}
            if csi.get("driver") == "secrets-store.csi.k8s.io":
                add(
                    f"csi:{volume_name}",
                    f"Secrets Store CSI projection in volume '{volume_name}'",
                )

        return targets

    def _is_projection_refresh_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        targets: set[str],
    ) -> bool:
        if not self._event_involves_pod(event, pod):
            return False

        text = " ".join(
            [
                self._reason(event),
                self._message(event),
                self._source_component(event),
            ]
        ).lower()

        reason = self._reason(event).lower()

        if (
            reason not in self.PROJECTION_RELATED_REASONS
            and not any(marker in text for marker in self.REFRESH_FAILURE_MARKERS)
        ):
            return False

        if any(marker in text for marker in self.REFRESH_FAILURE_MARKERS):
            return True

        return any(target.lower() in text for target in targets)

    def _is_stale_projection_signal(self, event: dict[str, Any]) -> bool:
        text = f"{self._reason(event)} {self._message(event)}".lower()
        return any(marker in text for marker in self.STALE_CONTENT_MARKERS)

    def _ordered_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        indexed = list(enumerate(recent))

        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _duration_for_predicate(
        self,
        timeline: Timeline,
        predicate: Callable[[dict[str, Any]], bool],
    ) -> float:
        try:
            return max(0.0, timeline.duration_between(predicate))
        except Exception:
            return 0.0

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        namespace, pod_name = self._pod_key(pod)

        targets = self._collect_projection_targets(pod)
        if not targets:
            return None

        ordered = self._ordered_events(timeline)

        refresh_failures = [
            event
            for event in ordered
            if self._is_projection_refresh_failure(
                event,
                pod,
                set(targets),
            )
        ]

        if len(refresh_failures) < self.MIN_FAILURE_EVENTS:
            return None

        stale_signals = [
            event
            for event in refresh_failures
            if self._is_stale_projection_signal(event)
        ]

        duration_seconds = self._duration_for_predicate(
            timeline,
            lambda event: self._is_projection_refresh_failure(
                event,
                pod,
                set(targets),
            ),
        )

        if duration_seconds < self.MIN_FAILURE_DURATION_SECONDS:
            return None

        representative = max(
            refresh_failures,
            key=lambda event: (
                self._occurrences(event),
                self._message(event),
            ),
        )

        target_types: set[str] = set()
        for target in targets:
            target_types.add(target.split(":", 1)[0])

        total_occurrences = sum(
            self._occurrences(event)
            for event in refresh_failures
        )

        return {
            "namespace": namespace,
            "pod_name": pod_name,
            "targets": targets,
            "target_types": sorted(target_types),
            "refresh_failures": refresh_failures,
            "stale_signals": stale_signals,
            "duration_seconds": duration_seconds,
            "total_occurrences": total_occurrences,
            "representative_message": self._message(representative).strip(),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(
            pod,
            context,
        )

        if candidate is None:
            raise ValueError(
                "ProjectedVolumeRefreshFailure explain() called without match"
            )

        pod_name = candidate["pod_name"]
        namespace = candidate["namespace"]

        projection_summary = ", ".join(candidate["target_types"])

        evidence = [
            f"Pod {namespace}/{pod_name} uses projected volume sources: {projection_summary}",
            f"Kubelet emitted {candidate['total_occurrences']} projected-volume refresh failure occurrence(s)",
            f"Projected volume refresh failures persisted for {candidate['duration_seconds'] / 60.0:.1f} minutes",
            f"Representative refresh failure: {candidate['representative_message']}",
        ]

        if candidate["stale_signals"]:
            evidence.append(
                "Events indicate kubelet continued serving stale projected content while refresh retries failed"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod depends on projected volume material that kubelet could not refresh successfully"
            ],
            "timeline:projected_volume_refresh": [
                "Repeated kubelet projection refresh failures persisted over time"
            ],
        }

        for target, references in candidate["targets"].items():
            object_evidence[target] = references + [
                "Projected resource refresh repeatedly failed"
            ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_USES_PROJECTED_VOLUME",
                    message="Pod depends on dynamically refreshed projected volume content",
                    role="configuration_context",
                ),
                Cause(
                    code="PROJECTED_VOLUME_REFRESH_FAILURE",
                    message="Kubelet or projection provider cannot refresh projected volume data",
                    role="storage_root",
                    blocking=True,
                ),
                Cause(
                    code="PROJECTED_CONTENT_STALE_OR_UNAVAILABLE",
                    message="Projected Secrets, ConfigMaps, service account tokens, or CSI-backed content become stale or unavailable",
                    role="storage_intermediate",
                ),
                Cause(
                    code="WORKLOAD_DEPENDS_ON_REFRESHED_CONTENT",
                    message="Workload behavior is degraded because refreshed projected content is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Projected volume refresh is failing",
            "confidence": 0.96,
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Kubelet cannot fetch updated Secret or ConfigMap objects from the API server",
                "ServiceAccount TokenRequest API calls are timing out or failing authorization",
                "Secrets Store CSI provider cannot refresh external secret material",
                "Projection atomic writer operations are failing because of filesystem, permission, or node-level issues",
                "API server, DNS, TLS, or network instability is interrupting projection refresh operations",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Inspect kubelet logs for projected volume or atomic writer errors",
                "Check API server connectivity and TokenRequest API health",
                "Inspect Secrets Store CSI driver/provider logs if CSI projections are involved",
                "Verify Secret and ConfigMap objects still exist and can be fetched from the node",
            ],
        }