from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class InitContainerResourceStarvationRule(FailureRule):
    """
    Detects init containers that repeatedly fail during bootstrap because they
    exceed runtime resource limits, preventing main containers from starting.

    Real-world behavior:
    - the Pod is already scheduled, so scheduler-level insufficient-capacity
      rules are no longer the best explanation
    - an init container can repeatedly OOM during migration/bootstrap work
    - kubelet retries the init container and the Pod stays stuck in
      PodInitializing/ContainerCreating, so the main workload never starts
    """

    name = "InitContainerResourceStarvation"
    category = "Compound"
    priority = 77
    deterministic = True
    phases = ["Pending", "Running", "Init"]
    container_states = ["waiting", "terminated"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    blocks = [
        "InitContainerBlocksMain",
        "InitContainerFailure",
        "OOMKilled",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 20
    MAX_BACKOFF_DELAY_SECONDS = 600
    MAIN_WAITING_REASONS = {"PodInitializing", "ContainerCreating"}
    CACHE_KEY = "_init_container_resource_starvation_candidate"

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

    def _init_spec(self, pod: dict[str, Any], name: str) -> dict[str, Any]:
        for container in pod.get("spec", {}).get("initContainers", []) or []:
            if container.get("name") == name:
                return container
        return {}

    def _blocked_main_containers(
        self, pod: dict[str, Any]
    ) -> list[dict[str, str]] | None:
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        if not spec_containers:
            return None

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        statuses_by_name = {
            str(status.get("name", "")): status
            for status in statuses
            if status.get("name")
        }

        blocked: list[dict[str, str]] = []
        for container in spec_containers:
            name = str(container.get("name", ""))
            if not name:
                continue

            status = statuses_by_name.get(name, {})
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}

            if state.get("running") or state.get("terminated"):
                return None

            if int(status.get("restartCount", 0) or 0) > 0:
                return None

            waiting_reason = str(waiting.get("reason", "") or "PodInitializing")
            if waiting_reason not in self.MAIN_WAITING_REASONS:
                return None

            blocked.append({"name": name, "reason": waiting_reason})

        return blocked or None

    def _backoff_events(
        self,
        timeline: Timeline,
        init_container_name: str,
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        lowered_name = init_container_name.lower()
        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            if str(event.get("reason", "")) != "BackOff":
                continue

            message = str(event.get("message", "")).lower()
            if lowered_name in message or "failed init container" in message:
                matches.append(event)

        return matches

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        blocked_main = self._blocked_main_containers(pod)
        if not blocked_main:
            return None

        best: dict[str, Any] | None = None
        for status in pod.get("status", {}).get("initContainerStatuses", []) or []:
            container_name = str(status.get("name", ""))
            if not container_name:
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

            init_spec = self._init_spec(pod, container_name)
            limits = (init_spec.get("resources", {}) or {}).get("limits", {}) or {}
            requests = (init_spec.get("resources", {}) or {}).get("requests", {}) or {}
            memory_limit = limits.get("memory")
            memory_request = requests.get("memory")

            candidate = {
                "container_name": container_name,
                "restart_count": restart_count,
                "delay": delay,
                "memory_limit": memory_limit,
                "memory_request": memory_request,
                "blocked_main": blocked_main,
                "latest_backoff_message": str(
                    backoff_events[-1].get("message", "")
                ).strip(),
                "exit_code": last_terminated.get("exitCode"),
            }

            if best is None or (
                candidate["restart_count"],
                len(backoff_events),
                candidate["container_name"],
            ) > (
                best["restart_count"],
                len(best["backoff_events"]),
                best["container_name"],
            ):
                candidate["backoff_events"] = backoff_events
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
            raise ValueError(
                "InitContainerResourceStarvation explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        init_name = str(candidate["container_name"])
        main_name = str(candidate["blocked_main"][0]["name"])
        main_reason = str(candidate["blocked_main"][0]["reason"])
        memory_limit = candidate.get("memory_limit")
        memory_request = candidate.get("memory_request")
        restart_count = int(candidate["restart_count"])
        delay = float(candidate["delay"])
        exit_code = candidate.get("exit_code")

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_CONTAINER_BOOTSTRAP_WORKLOAD",
                    message=f"Init container '{init_name}' performs bootstrap work before the main workload can start",
                    role="workload_context",
                ),
                Cause(
                    code="INIT_CONTAINER_OOM_RESOURCE_STARVATION",
                    message=f"Init container '{init_name}' is repeatedly exhausting its runtime memory budget",
                    role="resource_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBELET_RETRIES_INIT_CONTAINER",
                    message="Kubelet keeps retrying the failed init container instead of advancing to normal containers",
                    role="platform_semantics",
                ),
                Cause(
                    code="MAIN_STARTUP_STILL_BLOCKED",
                    message=f"Main container '{main_name}' remains blocked behind init container completion",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Init container '{init_name}' lastState shows OOMKilled before the current CrashLoopBackOff",
            f"Main container '{main_name}' has not started and remains waiting: {main_reason}",
            f"First BackOff retry for init container '{init_name}' began {delay:.1f}s after the recorded OOMKilled termination",
            f"Latest init container BackOff: {candidate['latest_backoff_message']}",
        ]
        if memory_limit or memory_request:
            evidence.append(
                f"Init container memory request/limit: request={memory_request or '<unset>'}, limit={memory_limit or '<unset>'}"
            )
        if exit_code is not None:
            evidence.append(f"OOMKilled termination exit code was {exit_code}")

        object_items = [
            f"Container restarted {restart_count} times after OOMKilled",
        ]
        if memory_limit or memory_request:
            object_items.append(
                f"memory request={memory_request or '<unset>'}, limit={memory_limit or '<unset>'}"
            )

        return {
            "root_cause": "Init container is resource-starved and keeps OOM-killing before main startup",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is stuck in initialization because the init container cannot complete within its memory budget"
                ],
                f"container:{init_name}": object_items,
                f"container:{main_name}": [
                    f"Main container is still waiting with reason {main_reason}"
                ],
            },
            "likely_causes": [
                "The init container memory limit is too low for migrations, decompression, or bootstrap data loading",
                "A recent bootstrap script or image change increased peak memory usage during initialization",
                "Node-level memory pressure is amplifying init-container startup memory spikes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {init_name} --previous",
                "Review init-container memory requests and limits against real bootstrap usage",
                "Inspect the init workload for data expansion, migrations, or cache warmup steps that spike memory",
            ],
        }
