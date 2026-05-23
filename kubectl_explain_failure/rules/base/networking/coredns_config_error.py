from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CoreDNSConfigErrorRule(FailureRule):
    """
    Detects cluster-wide DNS failures caused by invalid CoreDNS configuration.

    Real-world behavior:
    - application Pods report generic DNS lookup failures
    - CoreDNS emits Corefile parse, reload, loop, or plugin errors
    - the kube-system/coredns ConfigMap often contains the bad Corefile that
      made CoreDNS fail or answer incorrectly

    This is more specific than CoreDNSUnavailable: it identifies the bad
    CoreDNS config as the root, not merely the degraded DNS backend.
    """

    name = "CoreDNSConfigError"
    category = "Networking"
    severity = "High"
    priority = 76
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "configmap",
            "pod",
            "service",
            "endpoints",
            "endpointslice",
        ],
    }

    blocks = [
        "CoreDNSUnavailable",
        "DNSResolutionFailure",
        "DNSFailureThenCrashLoop",
        "ServiceEndpointsEmpty",
        "EndpointSliceMissing",
    ]

    WINDOW_MINUTES = 20

    DNS_FAILURE_MARKERS = (
        "dns lookup failed",
        "dns resolution",
        "cannot resolve",
        "could not resolve",
        "failed to resolve",
        "lookup ",
        "no such host",
        "server misbehaving",
        "temporary failure in name resolution",
        "servfail",
    )
    DNS_TRANSPORT_MARKERS = (
        "read udp",
        "read tcp",
        "i/o timeout",
        "connection refused",
    )
    NON_DNS_EXCLUSIONS = (
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "x509:",
        "certificate",
    )

    COREDNS_IDENTIFIERS = (
        "coredns",
        "kube-dns",
        "corefile",
    )
    COREDNS_CONFIG_MARKERS = (
        "corefile",
        "failed to load config",
        "failed to reload",
        "reload: error",
        "error during parsing",
        "failed to parse",
        "parse error",
        "syntax error",
        "unknown directive",
        "unknown property",
        "no plugin found",
        "plugin/loop",
        "loop detected",
        "invalid plugin",
        "invalid config",
        "panic",
    )
    CONFIG_RECOVERY_MARKERS = (
        "reload successful",
        "successfully reloaded",
        "reload complete",
        "running configuration",
    )
    COMMON_COREFILE_TYPOS = (
        "kubernets",
        "forwrd",
    )
    LOOKUP_TARGET_RE = re.compile(
        r"lookup\s+([a-z0-9.-]+)",
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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _targets_current_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind", "") or "").lower()
        if kind and kind != "pod":
            return False

        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _is_workload_dns_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if not self._targets_current_pod(event, pod):
            return False
        message = self._message(event).lower()
        if any(marker in message for marker in self.NON_DNS_EXCLUSIONS):
            return False
        if any(marker in message for marker in self.DNS_FAILURE_MARKERS):
            return True
        return ":53" in message and any(
            marker in message for marker in self.DNS_TRANSPORT_MARKERS
        )

    def _is_any_workload_dns_failure(self, event: dict[str, Any]) -> bool:
        message = self._message(event).lower()
        if any(marker in message for marker in self.NON_DNS_EXCLUSIONS):
            return False
        if any(marker in message for marker in self.DNS_FAILURE_MARKERS):
            return True
        return ":53" in message and any(
            marker in message for marker in self.DNS_TRANSPORT_MARKERS
        )

    def _lookup_target(self, message: str) -> str | None:
        matches = self.LOOKUP_TARGET_RE.findall(message)
        for candidate in reversed(matches):
            lowered = candidate.lower().strip(".")
            if lowered not in {"failed", "dns"}:
                return lowered
        return None

    def _affected_pods(self, events: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        for event in events:
            involved = event.get("involvedObject", {})
            if not isinstance(involved, dict):
                continue
            if str(involved.get("kind", "") or "").lower() != "pod":
                continue
            namespace = str(involved.get("namespace") or "default")
            name = str(involved.get("name") or "")
            if not name or namespace == "kube-system":
                continue
            ref = f"{namespace}/{name}"
            if ref not in names:
                names.append(ref)
        return names

    def _event_involves_coredns(self, event: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        involved_text = ""
        if isinstance(involved, dict):
            involved_text = " ".join(
                str(value).lower()
                for value in (
                    involved.get("namespace"),
                    involved.get("name"),
                    involved.get("kind"),
                    involved.get("fieldPath"),
                )
                if value
            )
        text = f"{involved_text} {self._message(event).lower()}"
        return any(identifier in text for identifier in self.COREDNS_IDENTIFIERS)

    def _is_coredns_config_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_coredns(event):
            return False
        text = f"{self._reason(event)} {self._message(event)}".lower()
        return any(marker in text for marker in self.COREDNS_CONFIG_MARKERS)

    def _is_config_recovery_event(self, event: dict[str, Any]) -> bool:
        if not self._event_involves_coredns(event):
            return False
        message = self._message(event).lower()
        return any(marker in message for marker in self.CONFIG_RECOVERY_MARKERS)

    def _coredns_configmaps(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        configmaps = context.get("objects", {}).get("configmap", {}) or {}
        matches: list[dict[str, Any]] = []
        for configmap in configmaps.values():
            if not isinstance(configmap, dict):
                continue
            metadata = configmap.get("metadata", {})
            if metadata.get("name") != "coredns":
                continue
            if metadata.get("namespace", "kube-system") != "kube-system":
                continue
            matches.append(configmap)
        return matches

    def _corefile_text(self, configmap: dict[str, Any]) -> str:
        data = configmap.get("data", {}) or {}
        corefile = data.get("Corefile")
        return corefile if isinstance(corefile, str) else ""

    def _corefile_issues(
        self,
        context: dict[str, Any],
        *,
        saw_loop_event: bool,
    ) -> list[str]:
        issues: list[str] = []
        for configmap in self._coredns_configmaps(context):
            corefile = self._corefile_text(configmap)
            lowered = corefile.lower()
            if not corefile:
                continue

            if corefile.count("{") != corefile.count("}"):
                issues.append("CoreDNS Corefile has unbalanced braces")

            for typo in self.COMMON_COREFILE_TYPOS:
                if typo in lowered:
                    issues.append(
                        f"CoreDNS Corefile contains suspicious directive '{typo}'"
                    )

            recursive_forward_markers = (
                "forward . 127.0.0.1",
                "forward . localhost",
                "forward . 10.96.0.10",
                "proxy . 127.0.0.1",
                "proxy . 10.96.0.10",
            )
            if any(marker in lowered for marker in recursive_forward_markers):
                issues.append("CoreDNS Corefile forwards DNS back to CoreDNS itself")

            if saw_loop_event and "forward . /etc/resolv.conf" in lowered:
                issues.append(
                    "CoreDNS Corefile forwards through node resolv.conf while CoreDNS reported a forwarding loop"
                )

        return list(dict.fromkeys(issues))

    def _config_recovered_after(
        self,
        timeline: Timeline,
        latest_config_error_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if not self._is_config_recovery_event(event):
                continue
            event_at = self._event_time(event)
            if (
                latest_config_error_at is None
                or event_at is None
                or event_at >= latest_config_error_at
            ):
                return True
        return False

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        recent_events = self._ordered_recent_events(timeline)
        current_pod_dns_events = [
            event
            for event in recent_events
            if self._is_workload_dns_failure(event, pod)
        ]
        if not current_pod_dns_events:
            return None

        all_dns_events = [
            event for event in recent_events if self._is_any_workload_dns_failure(event)
        ]
        config_events = [
            event for event in recent_events if self._is_coredns_config_event(event)
        ]
        saw_loop_event = any(
            "loop" in self._message(event).lower() for event in config_events
        )
        corefile_issues = self._corefile_issues(
            context,
            saw_loop_event=saw_loop_event,
        )

        if not config_events and not corefile_issues:
            return None

        latest_config_error_at = (
            self._event_time(config_events[-1]) if config_events else None
        )
        if config_events and self._config_recovered_after(
            timeline,
            latest_config_error_at,
        ):
            return None

        representative_dns = current_pod_dns_events[-1]
        representative_config_event = config_events[-1] if config_events else None
        affected_pods = self._affected_pods(all_dns_events)
        dns_occurrences = sum(self._occurrences(event) for event in all_dns_events)
        current_pod_occurrences = sum(
            self._occurrences(event) for event in current_pod_dns_events
        )
        config_occurrences = sum(self._occurrences(event) for event in config_events)
        duration_seconds = timeline.duration_between(
            lambda event: self._is_any_workload_dns_failure(event)
            or self._is_coredns_config_event(event)
        )

        return {
            "representative_dns_message": self._message(representative_dns),
            "representative_config_message": (
                self._message(representative_config_event)
                if representative_config_event
                else ""
            ),
            "lookup_target": self._lookup_target(self._message(representative_dns)),
            "affected_pods": affected_pods,
            "dns_occurrences": dns_occurrences,
            "current_pod_occurrences": current_pod_occurrences,
            "config_occurrences": config_occurrences,
            "corefile_issues": corefile_issues,
            "duration_seconds": duration_seconds,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        return (
            isinstance(timeline, Timeline)
            and self._best_candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CoreDNSConfigError requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError("CoreDNSConfigError explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")
        affected_pods_text = (
            ", ".join(candidate["affected_pods"])
            if candidate["affected_pods"]
            else f"{namespace}/{pod_name}"
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOADS_REQUIRE_CLUSTER_DNS",
                    message="Workloads depend on CoreDNS for cluster service discovery",
                    role="runtime_context",
                ),
                Cause(
                    code="COREDNS_CONFIG_INVALID",
                    message="CoreDNS is loading an invalid or recursively broken Corefile",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="CLUSTER_DNS_RESOLUTION_BROKEN",
                    message="Pod-local DNS lookups fail because CoreDNS cannot serve the configured zone correctly",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} has DNS failures while CoreDNS reports configuration errors",
            f"Representative workload DNS failure: {candidate['representative_dns_message']}",
            f"Observed {candidate['current_pod_occurrences']} DNS failure occurrence(s) for the current Pod within {self.WINDOW_MINUTES} minutes",
            f"Observed {candidate['dns_occurrences']} DNS failure occurrence(s) across affected workload Pod(s) within {self.WINDOW_MINUTES} minutes",
            f"Affected workload Pod(s): {affected_pods_text}",
        ]

        if candidate["representative_config_message"]:
            evidence.append(
                f"Representative CoreDNS config error: {candidate['representative_config_message']}"
            )
        if candidate["config_occurrences"]:
            evidence.append(
                f"Observed {candidate['config_occurrences']} CoreDNS config error occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )
        if candidate["lookup_target"]:
            evidence.append(
                f"DNS failures target hostname '{candidate['lookup_target']}'"
            )
        evidence.extend(candidate["corefile_issues"])
        if candidate["duration_seconds"]:
            evidence.append(
                f"CoreDNS config and workload DNS failure signals persisted for {candidate['duration_seconds']/60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                candidate["representative_dns_message"],
            ],
            "configmap:coredns": (
                candidate["corefile_issues"]
                or ["CoreDNS ConfigMap is implicated by Corefile parse/reload errors"]
            ),
        }
        if candidate["representative_config_message"]:
            object_evidence["timeline:coredns"] = [
                candidate["representative_config_message"]
            ]

        return {
            "root_cause": "CoreDNS configuration error is breaking cluster DNS",
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The kube-system/coredns ConfigMap contains an invalid Corefile directive or syntax error",
                "CoreDNS is forwarding recursively to itself or through a node resolver that points back to kube-dns",
                "A recent CoreDNS ConfigMap rollout introduced an invalid plugin stanza or zone block",
                "CoreDNS reload failed, so all Pods see generic DNS lookup failures while the root cause is shared config",
            ],
            "suggested_checks": [
                "kubectl -n kube-system get configmap coredns -o yaml",
                "kubectl -n kube-system logs -l k8s-app=kube-dns --tail=100",
                "kubectl -n kube-system describe configmap coredns",
                "Validate the Corefile syntax and plugin names before rolling CoreDNS",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
