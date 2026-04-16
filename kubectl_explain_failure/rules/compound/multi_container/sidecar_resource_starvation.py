from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class SidecarResourceStarvationRule(FailureRule):
    """
    Detects multi-container pods where a recognized sidecar is repeatedly
    OOM-killed and then restarted into CrashLoopBackOff while the primary
    workload remains healthy.

    Real-world behavior:
    - service-mesh proxies, agents, and log collectors often have independent
      memory envelopes from the main workload
    - the primary application can stay Ready while the sidecar repeatedly
      exceeds its memory limit and kubelet restarts it
    - this is a stronger explanation than a generic sidecar crashloop because
      the termination reason and restart timing show resource starvation
    """

    name = "SidecarResourceStarvation"
    category = "Compound"
    priority = 79
    deterministic = True

    phases = ["Running", "CrashLoopBackOff"]
    container_states = ["waiting", "terminated", "running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "SidecarCrashLoop",
        "OOMKilled",
        "OOMKilledThenCrashLoop",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "MultiContainerPartialFailure",
    ]

    WINDOW_MINUTES = 20
    MAX_BACKOFF_DELAY_SECONDS = 600
    CACHE_KEY = "_sidecar_resource_starvation_candidate"

    def _event_timestamp(self, event: dict[str, Any]):
        timestamp = (
            event.get("eventTime")
            or event.get("firstTimestamp")
            or event.get("lastTimestamp")
            or event.get("timestamp")
        )
        if not timestamp:
            return None
        try:
            return parse_time(timestamp)
        except Exception:
            return None

    def _terminated_at(self, status: dict[str, Any]):
        terminated = (status.get("lastState", {}) or {}).get("terminated") or {}
        finished_at = terminated.get("finishedAt")
        if not finished_at:
            return None
        try:
            return parse_time(finished_at)
        except Exception:
            return None

    def _sidecar_spec(self, pod: dict[str, Any], name: str) -> dict[str, Any]:
        for container in pod.get("spec", {}).get("containers", []) or []:
            if container.get("name") == name:
                return container
        return {}

    def _backoff_events(
        self,
        timeline: Timeline,
        container_name: str,
    ) -> list[dict[str, Any]]:
        lowered_name = (container_name or "").lower()
        matches: list[dict[str, Any]] = []

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if str(event.get("reason", "")) != "BackOff":
                continue

            message = str(event.get("message", "")).lower()
            if lowered_name and lowered_name not in message:
                involved = event.get("involvedObject", {}) or {}
                field_path = str(involved.get("fieldPath", "")).lower()
                if lowered_name not in field_path:
                    continue

            matches.append(event)

        return matches

    def _healthy_primary(self, pod: dict[str, Any]) -> dict[str, Any] | None:
        primaries: list[dict[str, Any]] = []

        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            name = str(status.get("name", ""))
            if self._is_sidecar(pod, name):
                continue

            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                return None

            if bool(status.get("ready")):
                primaries.append(status)

        if not primaries:
            return None

        return max(
            primaries, key=lambda status: int(status.get("restartCount", 0) or 0)
        )

    def _is_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        return is_recognized_sidecar_container(pod, container_name)

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        primary = self._healthy_primary(pod)
        if primary is None:
            return None

        best: dict[str, Any] | None = None
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            container_name = str(status.get("name", ""))
            if not container_name or not self._is_sidecar(pod, container_name):
                continue

            last_terminated = (status.get("lastState", {}) or {}).get(
                "terminated"
            ) or {}
            if last_terminated.get("reason") != "OOMKilled":
                continue

            terminated_at = self._terminated_at(status)
            if terminated_at is None:
                continue

            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") != "CrashLoopBackOff":
                continue

            restart_count = int(status.get("restartCount", 0) or 0)
            if restart_count < 1:
                continue

            backoff_events = self._backoff_events(timeline, container_name)
            if not backoff_events:
                continue

            first_backoff = min(
                backoff_events,
                key=lambda event: self._event_timestamp(event)
                or parse_time("1970-01-01T00:00:00+00:00"),
            )
            first_backoff_ts = self._event_timestamp(first_backoff)
            if first_backoff_ts is None:
                continue

            delay = (first_backoff_ts - terminated_at).total_seconds()
            if delay < 0 or delay > self.MAX_BACKOFF_DELAY_SECONDS:
                continue

            spec = self._sidecar_spec(pod, container_name)
            limits = (spec.get("resources", {}) or {}).get("limits", {}) or {}
            requests = (spec.get("resources", {}) or {}).get("requests", {}) or {}

            candidate = {
                "sidecar_name": container_name,
                "sidecar_status": status,
                "primary_name": str(primary.get("name", "<container>")),
                "restart_count": restart_count,
                "delay": delay,
                "memory_limit": limits.get("memory"),
                "memory_request": requests.get("memory"),
                "latest_backoff_message": str(
                    backoff_events[-1].get("message", "")
                ).strip(),
                "exit_code": last_terminated.get("exitCode"),
                "backoff_events": backoff_events,
            }

            if best is None or (
                candidate["restart_count"],
                len(candidate["backoff_events"]),
                candidate["sidecar_name"],
            ) > (
                best["restart_count"],
                len(best["backoff_events"]),
                best["sidecar_name"],
            ):
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError("SidecarResourceStarvation explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sidecar_name = str(candidate["sidecar_name"])
        primary_name = str(candidate["primary_name"])
        restart_count = int(candidate["restart_count"])
        delay = float(candidate["delay"])
        memory_limit = candidate.get("memory_limit")
        memory_request = candidate.get("memory_request")
        exit_code = candidate.get("exit_code")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_ROLE_IDENTIFIED",
                    message=f"Container '{sidecar_name}' is acting as a sidecar alongside the primary workload",
                    role="workload_context",
                ),
                Cause(
                    code="SIDECAR_OOM_RESOURCE_STARVATION",
                    message=f"Sidecar container '{sidecar_name}' is repeatedly exhausting its runtime memory budget",
                    role="resource_root",
                    blocking=True,
                ),
                Cause(
                    code="SIDECAR_CRASHLOOP_AFTER_OOM",
                    message="Kubelet keeps restarting the sidecar after OOMKilled termination and enters restart backoff",
                    role="platform_semantics",
                ),
                Cause(
                    code="PRIMARY_REMAINS_HEALTHY_WHILE_SIDECAR_DEGRADES",
                    message=f"Primary container '{primary_name}' remains healthy while the resource-starved sidecar degrades pod functionality",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Recognized sidecar '{sidecar_name}' lastState shows OOMKilled before the current CrashLoopBackOff",
            f"Primary container '{primary_name}' remains Ready while the sidecar is restarting",
            f"First BackOff retry for sidecar '{sidecar_name}' began {delay:.1f}s after the recorded OOMKilled termination",
            f"Latest sidecar BackOff: {candidate['latest_backoff_message']}",
        ]
        if memory_limit or memory_request:
            evidence.append(
                f"Sidecar memory request/limit: request={memory_request or '<unset>'}, limit={memory_limit or '<unset>'}"
            )
        if exit_code is not None:
            evidence.append(f"OOMKilled termination exit code was {exit_code}")

        sidecar_items = [f"Container restarted {restart_count} times after OOMKilled"]
        if memory_limit or memory_request:
            sidecar_items.append(
                f"memory request={memory_request or '<unset>'}, limit={memory_limit or '<unset>'}"
            )

        return {
            "root_cause": "Sidecar is resource-starved and keeps OOM-killing while the primary workload remains healthy",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod has a healthy primary workload but the sidecar is repeatedly OOM-killing within its memory budget"
                ],
                f"container:{sidecar_name}": sidecar_items,
                f"container:{primary_name}": [
                    "Primary workload container remains Ready while the sidecar is failing"
                ],
            },
            "likely_causes": [
                "The sidecar memory limit is too low for proxy bootstrap, buffering, telemetry, or steady-state traffic",
                "A recent mesh, agent, or logging configuration change increased the sidecar's peak memory footprint",
                "Node-level memory pressure is amplifying memory spikes for the sidecar process",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {sidecar_name} --previous",
                "Review sidecar memory requests and limits against real proxy or agent usage",
                "Inspect recent sidecar config, telemetry, or bootstrap changes that could increase memory consumption",
            ],
        }
