from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class DNSFailureThenCrashLoopRule(FailureRule):
    """
    Detects repeated DNS resolution failures that lead the same container into
    CrashLoopBackOff.

    Real-world behavior:
    - startup code often resolves required upstream hosts before the process can
      become healthy
    - if DNS resolution fails repeatedly, the process exits quickly and kubelet
      begins restart backoff
    - the visible CrashLoopBackOff is downstream of the unresolved hostname
    """

    name = "DNSFailureThenCrashLoop"
    category = "Compound"
    priority = 59
    deterministic = False

    phases = ["Pending", "Running"]
    container_states = ["waiting", "terminated"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    optional_objects = ["service"]

    blocks = [
        "DNSResolutionFailure",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 20
    MAX_DNS_TO_BACKOFF = timedelta(minutes=5)
    MIN_SEQUENCES = 2
    BACKOFF_REASONS = {"backoff", "crashloopbackoff"}
    DNS_MARKERS = (
        "dns lookup failed",
        "cannot resolve",
        "lookup ",
        "no such host",
        "temporary failure in name resolution",
        "server misbehaving",
        "name resolution",
        "dns",
    )
    EXCLUDED_MARKERS = (
        "failed to pull image",
        "pulling image",
        "errimagepull",
        "imagepullbackoff",
    )
    LOOKUP_TARGET_RE = re.compile(
        r"lookup\s+([a-z0-9.-]+)",
        re.IGNORECASE,
    )
    LOOKUP_ON_RE = re.compile(
        r"lookup\s+([a-z0-9.-]+)\s+on\s+[a-z0-9.:]+",
        re.IGNORECASE,
    )
    SERVICE_TARGET_RE = re.compile(
        r"([a-z0-9-]+)\.([a-z0-9-]+)\.svc(?:\.cluster\.local)?",
        re.IGNORECASE,
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

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        enumerated = list(enumerate(recent))

        def sort_key(item: tuple[int, dict[str, Any]]) -> tuple[int, datetime, int]:
            index, event = item
            ts = self._event_time(event)
            if ts is None:
                return (1, datetime.min, index)
            return (0, ts, index)

        return [event for _, event in sorted(enumerated, key=sort_key)]

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", ""))

    def _event_message_lower(self, event: dict[str, Any]) -> str:
        return self._event_message(event).lower()

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        raw_count = event.get("count", 1)
        try:
            count = int(raw_count)
        except Exception:
            return 1
        return max(1, count)

    def _candidate_container_names(self, pod: dict[str, Any]) -> list[str]:
        names = [
            str(status.get("name", "")).strip()
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if status.get("name")
        ]
        if names:
            return names
        return [
            str(container.get("name", "")).strip()
            for container in pod.get("spec", {}).get("containers", []) or []
            if container.get("name")
        ]

    def _status_for_container(
        self,
        pod: dict[str, Any],
        container_name: str,
    ) -> dict[str, Any]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            if str(status.get("name", "")).strip() == container_name:
                return status
        return {}

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        if not container_name:
            return assume_single_container

        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if container_name.lower() in field_path:
                return True

        message = self._event_message_lower(event)
        patterns = (
            f'container "{container_name.lower()}"',
            f"container {container_name.lower()}",
            f"failed container {container_name.lower()}",
            f"containers{{{container_name.lower()}}}",
        )
        if any(pattern in message for pattern in patterns):
            return True

        return assume_single_container and "container " not in message

    def _extract_lookup_target(self, message: str) -> str | None:
        match = self.LOOKUP_ON_RE.search(message)
        if match:
            return match.group(1).lower()
        matches = self.LOOKUP_TARGET_RE.findall(message)
        for candidate in reversed(matches):
            lowered = candidate.lower()
            if lowered not in {"failed", "dns"}:
                return lowered
        return None

    def _references_missing_service(
        self, target: str | None, context: dict[str, Any]
    ) -> bool:
        if not target:
            return False

        match = self.SERVICE_TARGET_RE.search(target)
        if not match:
            return False

        service_name = match.group(1).lower()
        services = context.get("objects", {}).get("service")
        if not isinstance(services, dict) or not services:
            return False

        return service_name not in {str(name).lower() for name in services.keys()}

    def _is_dns_failure_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
        context: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return None, None

        message = self._event_message_lower(event)
        if any(marker in message for marker in self.EXCLUDED_MARKERS):
            return None, None

        if not any(marker in message for marker in self.DNS_MARKERS):
            return None, None

        target = self._extract_lookup_target(message)
        if self._references_missing_service(target, context):
            return None, None

        return target, self._event_message(event)

    def _is_backoff_event(
        self,
        event: dict[str, Any],
        *,
        container_name: str,
        assume_single_container: bool,
    ) -> bool:
        if not self._container_event_match(
            event,
            container_name,
            assume_single_container=assume_single_container,
        ):
            return False

        reason = self._event_reason(event)
        message = self._event_message_lower(event)
        if reason in self.BACKOFF_REASONS:
            return True
        return (
            "crashloopbackoff" in message
            or "back-off restarting failed container" in message
        )

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        container_names = self._candidate_container_names(pod)
        if not container_names:
            return None

        assume_single_container = len(container_names) == 1
        best: dict[str, Any] | None = None

        for container_name in container_names:
            status = self._status_for_container(pod, container_name)
            restart_count = int(status.get("restartCount", 0) or 0)
            waiting_reason = (status.get("state", {}).get("waiting", {}) or {}).get(
                "reason"
            )
            crashloop_waiting = waiting_reason == "CrashLoopBackOff"
            last_terminated = status.get("lastState", {}).get("terminated", {}) or {}
            exit_code = last_terminated.get("exitCode")

            dns_events: list[dict[str, Any]] = []
            for event in ordered:
                target, raw_message = self._is_dns_failure_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                    context=context,
                )
                if raw_message is None:
                    continue
                dns_events.append(
                    {
                        "event": event,
                        "target": target,
                        "message": raw_message,
                    }
                )

            if not dns_events:
                continue

            backoff_events = [
                event
                for event in ordered
                if self._is_backoff_event(
                    event,
                    container_name=container_name,
                    assume_single_container=assume_single_container,
                )
            ]
            if not backoff_events:
                continue

            sequences: list[dict[str, Any]] = []
            used_backoff_indexes: set[int] = set()
            for dns_item in dns_events:
                dns_event = dns_item["event"]
                dns_time = self._event_time(dns_event)
                if dns_time is None:
                    continue

                for index, backoff_event in enumerate(backoff_events):
                    if index in used_backoff_indexes:
                        continue

                    backoff_time = self._event_time(backoff_event)
                    if backoff_time is None:
                        continue
                    if backoff_time < dns_time:
                        continue
                    if backoff_time - dns_time > self.MAX_DNS_TO_BACKOFF:
                        break

                    used_backoff_indexes.add(index)
                    sequences.append(
                        {
                            "dns_event": dns_event,
                            "backoff_event": backoff_event,
                            "target": dns_item["target"],
                            "dns_message": dns_item["message"],
                        }
                    )
                    break

            if not sequences:
                continue

            dns_occurrences = sum(
                self._occurrences(item["event"]) for item in dns_events
            )
            backoff_occurrences = sum(
                self._occurrences(event) for event in backoff_events
            )

            if not crashloop_waiting and restart_count < 2 and backoff_occurrences < 2:
                continue

            if len(sequences) < self.MIN_SEQUENCES and not (
                dns_occurrences >= 2
                and (restart_count >= 2 or backoff_occurrences >= 2)
            ):
                continue

            dominant_dns_message = max(
                {item["message"] for item in dns_events},
                key=lambda message: sum(
                    self._occurrences(item["event"])
                    for item in dns_events
                    if item["message"] == message
                ),
            )
            dominant_backoff_message = max(
                {self._event_message(event) for event in backoff_events},
                key=lambda message: sum(
                    self._occurrences(event)
                    for event in backoff_events
                    if self._event_message(event) == message
                ),
            )

            candidate = {
                "container_name": container_name,
                "restart_count": restart_count,
                "crashloop_waiting": crashloop_waiting,
                "sequence_count": len(sequences),
                "dns_occurrences": dns_occurrences,
                "backoff_occurrences": backoff_occurrences,
                "target": sequences[0]["target"],
                "dominant_dns_message": dominant_dns_message,
                "dominant_backoff_message": dominant_backoff_message,
                "exit_code": exit_code,
            }

            if best is None:
                best = candidate
                continue

            best_key = (
                best["sequence_count"],
                best["dns_occurrences"],
                best["backoff_occurrences"],
                best["restart_count"],
            )
            candidate_key = (
                candidate["sequence_count"],
                candidate["dns_occurrences"],
                candidate["backoff_occurrences"],
                candidate["restart_count"],
            )
            if candidate_key > best_key:
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        return self._best_candidate(pod, timeline, context) is not None

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("DNSFailureThenCrashLoop requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("DNSFailureThenCrashLoop explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        container_name = candidate["container_name"]
        restart_count = candidate["restart_count"]
        target = candidate["target"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="DNS_DEPENDENCY_REQUIRED_FOR_STARTUP",
                    message="Container startup depends on resolving a required hostname before the process can stabilize",
                    role="runtime_context",
                ),
                Cause(
                    code="REPEATED_DNS_RESOLUTION_FAILURE",
                    message="Repeated DNS resolution failures prevent the workload from completing startup successfully",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASHLOOP_AFTER_DNS_FAILURE",
                    message="Kubelet repeatedly restarts the container until it enters CrashLoopBackOff",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Timeline shows {candidate['sequence_count']} DNS-failure -> restart-backoff sequence(s) for container '{container_name}' within the recent incident window",
            f"Container '{container_name}' is now restartCount={restart_count} with a current CrashLoopBackOff state driven by repeated startup failures",
            f"Representative DNS failure: {candidate['dominant_dns_message']}",
            f"Representative BackOff: {candidate['dominant_backoff_message']}",
        ]
        if target:
            evidence.append(
                f"DNS failures consistently target hostname '{target}' before restart backoff begins"
            )
        if candidate["exit_code"] is not None:
            evidence.append(
                f"The most recent terminated state exited with code {candidate['exit_code']} before the current CrashLoopBackOff"
            )

        return {
            "root_cause": "Repeated DNS resolution failures are causing the container to crash and enter CrashLoopBackOff",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod is repeatedly restarting after DNS resolution failures"
                ],
                f"container:{container_name}": [
                    candidate["dominant_dns_message"],
                    candidate["dominant_backoff_message"],
                ],
            },
            "likely_causes": [
                "CoreDNS or upstream DNS forwarding is unavailable or misconfigured",
                "The application depends on a hostname that is missing from cluster or upstream DNS",
                "Startup logic exits immediately when DNS resolution fails instead of retrying gracefully",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {container_name} --previous",
                "kubectl get pods -n kube-system | grep coredns",
                "Verify the failing hostname from inside a debug pod and inspect the pod's resolv.conf",
            ],
        }
