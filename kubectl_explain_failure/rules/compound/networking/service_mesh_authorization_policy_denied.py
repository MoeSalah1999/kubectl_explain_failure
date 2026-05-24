from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.rules.multi_container_helpers import (
    is_recognized_sidecar_container,
    pod_has_sidecar_injection_signal,
)
from kubectl_explain_failure.timeline import Timeline, parse_time


class ServiceMeshAuthorizationPolicyDeniedRule(FailureRule):
    """
    Detects app-to-app failures caused by service-mesh authorization policy.

    Real-world behavior:
    - Istio AuthorizationPolicy, Linkerd policy, Consul intentions, or Envoy
      RBAC filters can deny L7 traffic after Kubernetes networking succeeds
    - application containers commonly see HTTP 403, RBAC denied, or upstream
      connect failures while Services and endpoints remain healthy
    - this is distinct from Kubernetes NetworkPolicy, which denies traffic at
      the CNI/L3-L4 layer and usually appears as timeout/refused/no-route
      connectivity rather than an explicit mesh authorization decision
    """

    name = "ServiceMeshAuthorizationPolicyDenied"
    category = "Compound"
    severity = "High"
    priority = 83
    deterministic = True

    phases = ["Running", "Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "authorizationpolicy",
            "serverauthorization",
            "httproute",
            "service",
            "endpoints",
            "endpointslice",
            "networkpolicy",
        ],
    }

    blocks = [
        "NetworkPolicyBlocked",
        "NetworkPolicyThenProbeFailure",
        "ServiceMeshSidecarNetworkBlock",
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
        "DNSResolutionFailure",
    ]

    WINDOW_MINUTES = 20
    MAX_DENIAL_TO_APP_GAP = timedelta(minutes=5)
    MIN_DENIAL_OCCURRENCES = 2
    CACHE_KEY = "_service_mesh_authorization_policy_denied_candidate"

    MESH_SIDECAR_NAMES = {
        "istio-proxy",
        "linkerd-proxy",
        "consul-connect-envoy",
        "envoy",
    }

    MESH_CONTEXT_MARKERS = (
        "envoy",
        "istio",
        "linkerd",
        "consul",
        "service mesh",
        "mesh",
        "sidecar",
        "proxy",
        "rbac",
        "authorizationpolicy",
        "serverauthorization",
        "intention",
    )

    MESH_POLICY_DENIAL_MARKERS = (
        "rbac: access denied",
        "rbac_access_denied",
        "envoy rbac",
        "denied by authorization policy",
        "authorization policy denied",
        "authorizationpolicy denied",
        "request denied by policy",
        "access denied by policy",
        "access denied",
        "permission denied",
        "http 403",
        "statuscode: 403",
        "status code 403",
        "403 forbidden",
        "forbidden by mesh",
        "linkerd policy denied",
        "serverauthorization denied",
        "consul intention denied",
        "intention denied",
    )

    NON_MESH_POLICY_MARKERS = (
        "networkpolicy",
        "network policy",
        "cilium network policy",
        "calico policy",
        "egress policy",
        "ingress policy",
    )

    APP_IMPACT_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "http probe failed with statuscode: 403",
        "http probe failed with statuscode: 503",
        "upstream connect error",
        "upstream request failed",
        "rbac: access denied",
        "403 forbidden",
        "access denied",
        "permission denied",
        "service unavailable",
    )

    POLICY_OBJECT_KINDS = (
        "authorizationpolicy",
        "serverauthorization",
        "meshtrafficpermission",
        "serviceintentions",
        "intention",
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
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("lastTimestamp"))
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

    def _event_involves_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject")
        if not isinstance(involved, dict):
            return False
        namespace, pod_name = self._pod_key(pod)
        kind = str(involved.get("kind") or "").lower()
        if kind and kind != "pod":
            return False
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _container_event_match(
        self,
        event: dict[str, Any],
        container_name: str,
        *,
        assume_single_container: bool,
    ) -> bool:
        lowered = container_name.lower()
        involved = event.get("involvedObject", {})
        if isinstance(involved, dict):
            field_path = str(involved.get("fieldPath", "")).lower()
            if field_path:
                return lowered in field_path

        message = self._message(event).lower()
        patterns = (
            f'container "{lowered}"',
            f"container {lowered}",
            f"failed container {lowered}",
            f"containers{{{lowered}}}",
            lowered,
        )
        if any(pattern in message for pattern in patterns):
            return True
        return assume_single_container and "container " not in message

    def _is_mesh_sidecar(self, pod: dict[str, Any], container_name: str) -> bool:
        lowered = container_name.lower()
        if lowered in self.MESH_SIDECAR_NAMES:
            return True
        if not is_recognized_sidecar_container(pod, container_name):
            return False
        return pod_has_sidecar_injection_signal(pod) and (
            "proxy" in lowered or "envoy" in lowered
        )

    def _mesh_sidecar_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if self._is_mesh_sidecar(pod, str(status.get("name", "")))
        ]

    def _primary_statuses(self, pod: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            status
            for status in pod.get("status", {}).get("containerStatuses", []) or []
            if not self._is_mesh_sidecar(pod, str(status.get("name", "")))
        ]

    def _has_mesh_context(self, text: str) -> bool:
        lowered = text.lower()
        return any(marker in lowered for marker in self.MESH_CONTEXT_MARKERS)

    def _looks_like_kubernetes_network_policy_denial(self, text: str) -> bool:
        lowered = text.lower()
        return any(marker in lowered for marker in self.NON_MESH_POLICY_MARKERS)

    def _is_mesh_authorization_denial(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        sidecar_names: set[str],
        *,
        assume_single_sidecar: bool,
    ) -> bool:
        combined = " ".join(
            [
                self._reason(event),
                self._message(event),
                self._source_component(event),
            ]
        )
        lowered = combined.lower()

        if self._looks_like_kubernetes_network_policy_denial(lowered):
            return False
        if not any(marker in lowered for marker in self.MESH_POLICY_DENIAL_MARKERS):
            return False
        if not self._has_mesh_context(lowered):
            return False

        source = self._source_component(event).lower()
        mesh_source = any(
            marker in source for marker in ("envoy", "istio", "linkerd", "consul")
        )

        if self._event_involves_pod(event, pod):
            if not sidecar_names:
                return True
            if any(
                self._container_event_match(
                    event,
                    sidecar_name,
                    assume_single_container=assume_single_sidecar,
                )
                for sidecar_name in sidecar_names
            ):
                return True
            return mesh_source

        return mesh_source

    def _is_application_impact(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        primary_names: set[str],
        *,
        assume_single_primary: bool,
    ) -> bool:
        if not self._event_involves_pod(event, pod):
            return False
        lowered = self._message(event).lower()
        if not any(marker in lowered for marker in self.APP_IMPACT_MARKERS):
            return False
        if not primary_names:
            return True
        return any(
            self._container_event_match(
                event,
                primary_name,
                assume_single_container=assume_single_primary,
            )
            for primary_name in primary_names
        )

    def _labels_match(
        self,
        selector: dict[str, Any] | None,
        labels: dict[str, str],
    ) -> bool:
        if selector is None:
            return False
        if not selector:
            return True

        for key, expected in (selector.get("matchLabels", {}) or {}).items():
            if labels.get(key) != expected:
                return False

        for expression in selector.get("matchExpressions", []) or []:
            key = expression.get("key")
            operator = expression.get("operator")
            values = expression.get("values", []) or []
            actual = labels.get(key)
            if operator == "In" and actual not in values:
                return False
            if operator == "NotIn" and actual in values:
                return False
            if operator == "Exists" and actual is None:
                return False
            if operator == "DoesNotExist" and actual is not None:
                return False
        return True

    def _policy_selects_pod(self, policy: dict[str, Any], pod: dict[str, Any]) -> bool:
        metadata = policy.get("metadata", {}) or {}
        pod_metadata = pod.get("metadata", {}) or {}
        if metadata.get("namespace", "default") != pod_metadata.get(
            "namespace", "default"
        ):
            return False

        labels = pod_metadata.get("labels", {}) or {}
        spec = policy.get("spec", {}) or {}
        selector = (
            spec.get("selector", {}).get("matchLabels")
            if isinstance(spec.get("selector"), dict)
            and "matchLabels" in spec.get("selector", {})
            else spec.get("selector")
        )
        if isinstance(selector, dict) and "matchLabels" not in selector:
            selector = {"matchLabels": selector}
        if self._labels_match(selector, labels):
            return True

        target_ref = spec.get("targetRef") or {}
        return bool(
            target_ref
            and str(target_ref.get("kind", "")).lower() in {"service", "pod"}
            and target_ref.get("name") in {pod_metadata.get("name"), labels.get("app")}
        )

    def _policy_action_denies(self, policy: dict[str, Any]) -> bool:
        spec_text = str(policy.get("spec", {}) or "").lower()
        return any(
            marker in spec_text
            for marker in (
                "'action': 'deny'",
                '"action": "deny"',
                "action': 'deny",
                "action=deny",
                "deny",
                "unauthenticated",
                "notprincipals",
                "serverauthorization",
            )
        )

    def _selected_mesh_policies(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        policies: list[dict[str, Any]] = []
        for kind in self.POLICY_OBJECT_KINDS:
            for obj in (objects.get(kind, {}) or {}).values():
                if not isinstance(obj, dict):
                    continue
                if self._policy_selects_pod(obj, pod) or self._policy_action_denies(
                    obj
                ):
                    policies.append(obj)
        return policies

    def _service_ready_evidence(
        self,
        context: dict[str, Any],
    ) -> tuple[list[str], dict[str, list[str]]]:
        objects = context.get("objects", {}) or {}
        evidence: list[str] = []
        object_evidence: dict[str, list[str]] = {}

        for name, service in (objects.get("service", {}) or {}).items():
            if not isinstance(service, dict):
                continue
            service_name = str(service.get("metadata", {}).get("name") or name)
            endpoint_count = 0
            endpoints = (objects.get("endpoints", {}) or {}).get(service_name)
            if isinstance(endpoints, dict):
                for subset in endpoints.get("subsets", []) or []:
                    endpoint_count += len(subset.get("addresses", []) or [])
            for slice_obj in (objects.get("endpointslice", {}) or {}).values():
                if not isinstance(slice_obj, dict):
                    continue
                labels = slice_obj.get("metadata", {}).get("labels", {}) or {}
                if labels.get("kubernetes.io/service-name") != service_name:
                    continue
                endpoint_count += sum(
                    1
                    for endpoint in slice_obj.get("endpoints", []) or []
                    if endpoint.get("conditions", {}).get("ready") is True
                )
            if endpoint_count:
                evidence.append(
                    f"Destination Service '{service_name}' has {endpoint_count} ready endpoint(s), making a Kubernetes NetworkPolicy or backend outage less likely"
                )
                object_evidence[f"service:{service_name}"] = [
                    f"{endpoint_count} ready endpoint(s) available while mesh authorization denies traffic"
                ]
        return evidence, object_evidence

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        sidecars = self._mesh_sidecar_statuses(pod)
        if not sidecars:
            return None
        if not pod_has_sidecar_injection_signal(pod) and not any(
            str(status.get("name", "")).lower() in self.MESH_SIDECAR_NAMES
            for status in sidecars
        ):
            return None

        ordered = self._ordered_recent_events(timeline)
        if not ordered:
            return None

        sidecar_names = {str(status.get("name", "")) for status in sidecars}
        primary_names = {
            str(status.get("name", ""))
            for status in self._primary_statuses(pod)
            if str(status.get("name", ""))
        }
        assume_single_sidecar = len(sidecar_names) == 1
        assume_single_primary = len(primary_names) <= 1

        denial_events = [
            event
            for event in ordered
            if self._is_mesh_authorization_denial(
                event,
                pod,
                sidecar_names,
                assume_single_sidecar=assume_single_sidecar,
            )
        ]
        denial_occurrences = sum(self._occurrences(event) for event in denial_events)
        if (
            len(denial_events) < self.MIN_DENIAL_OCCURRENCES
            and denial_occurrences < self.MIN_DENIAL_OCCURRENCES
        ):
            return None

        impact_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for denial_event in denial_events:
            denial_time = self._event_time(denial_event)
            if denial_time is None:
                continue
            for event in ordered:
                impact_time = self._event_time(event)
                if impact_time is None or impact_time < denial_time:
                    continue
                if impact_time - denial_time > self.MAX_DENIAL_TO_APP_GAP:
                    break
                if self._is_application_impact(
                    event,
                    pod,
                    primary_names,
                    assume_single_primary=assume_single_primary,
                ):
                    impact_pairs.append((denial_event, event))
                    break

        policies = self._selected_mesh_policies(pod, context)
        if not impact_pairs and not policies:
            return None

        service_evidence, service_object_evidence = self._service_ready_evidence(
            context
        )
        duration_seconds = timeline.duration_between(
            lambda event: self._is_mesh_authorization_denial(
                event,
                pod,
                sidecar_names,
                assume_single_sidecar=assume_single_sidecar,
            )
        )

        representative_denial = max(
            denial_events,
            key=lambda event: (self._occurrences(event), self._message(event)),
        )
        representative_impact = (
            max(
                (pair[1] for pair in impact_pairs),
                key=lambda event: (self._occurrences(event), self._message(event)),
            )
            if impact_pairs
            else None
        )
        policy_names = sorted(
            {
                str(policy.get("metadata", {}).get("name") or "<unknown>")
                for policy in policies
            }
        )

        return {
            "sidecar": sidecars[0],
            "denial_occurrences": denial_occurrences,
            "representative_denial_message": self._message(
                representative_denial
            ).strip(),
            "representative_impact_message": (
                self._message(representative_impact).strip()
                if representative_impact
                else None
            ),
            "impact_pairs": impact_pairs,
            "duration_seconds": max(0.0, duration_seconds),
            "policy_names": policy_names,
            "service_evidence": service_evidence,
            "service_object_evidence": service_object_evidence,
        }

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
                "ServiceMeshAuthorizationPolicyDenied explain() called without match"
            )

        metadata = pod.get("metadata", {}) or {}
        pod_name = str(metadata.get("name") or "<unknown>")
        namespace = str(metadata.get("namespace") or "default")
        sidecar_name = str(candidate["sidecar"].get("name") or "<sidecar>")
        policy_names = candidate["policy_names"] or ["<unknown>"]
        primary_policy = policy_names[0]
        duration_minutes = candidate["duration_seconds"] / 60.0

        evidence = [
            f"Pod {namespace}/{pod_name} uses service-mesh sidecar '{sidecar_name}' for app-to-app authorization",
            f"Observed {candidate['denial_occurrences']} mesh authorization denial occurrence(s) within {self.WINDOW_MINUTES} minutes",
            f"Representative mesh authorization denial: {candidate['representative_denial_message']}",
        ]
        if primary_policy != "<unknown>":
            evidence.append(
                f"Mesh authorization policy object '{primary_policy}' is present for this workload path"
            )
        if candidate["representative_impact_message"]:
            evidence.append(
                f"Representative application impact after mesh denial: {candidate['representative_impact_message']}"
            )
        if duration_minutes > 0:
            evidence.append(
                f"Mesh authorization denials persisted for {duration_minutes:.1f} minutes"
            )
        evidence.extend(candidate["service_evidence"])

        primary_statuses = self._primary_statuses(pod)
        primary_name = (
            str(primary_statuses[0].get("name"))
            if primary_statuses
            else "<application>"
        )
        object_evidence = {
            f"pod:{pod_name}": [
                "Application traffic reaches the mesh proxy but is denied by mesh authorization"
            ],
            f"container:{sidecar_name}": [
                candidate["representative_denial_message"],
            ],
            "timeline:mesh_authorization": [
                f"{candidate['denial_occurrences']} authorization denial occurrence(s) in the recent timeline"
            ],
        }
        if primary_policy != "<unknown>":
            object_evidence[f"authorizationpolicy:{primary_policy}"] = [
                "Mesh policy is the authorization layer implicated by the denial"
            ]
        if candidate["representative_impact_message"]:
            object_evidence[f"container:{primary_name}"] = [
                candidate["representative_impact_message"]
            ]
        for key, items in candidate["service_object_evidence"].items():
            object_evidence.setdefault(key, []).extend(items)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_MESH_AUTHORIZATION_ENFORCED",
                    message=f"Pod traffic is evaluated by service-mesh sidecar '{sidecar_name}' before reaching peer workloads",
                    role="network_context",
                ),
                Cause(
                    code="MESH_AUTHORIZATION_POLICY_DENIES_REQUEST",
                    message="A service-mesh authorization policy denies the app-to-app request after network connectivity succeeds",
                    role="authorization_root",
                    blocking=True,
                ),
                Cause(
                    code="KUBERNETES_NETWORKPOLICY_NOT_PRIMARY",
                    message="The denial is explicit mesh RBAC/authorization feedback rather than a CNI NetworkPolicy timeout",
                    role="policy_context",
                ),
                Cause(
                    code="APPLICATION_REQUESTS_FAIL_WITH_FORBIDDEN",
                    message="Application health checks or upstream calls fail because the mesh returns authorization denial",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Service mesh authorization policy denied app-to-app traffic",
            "confidence": 0.97 if primary_policy != "<unknown>" else 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Istio AuthorizationPolicy, Linkerd policy, or Consul intention denies the source identity, method, path, or destination",
                "The workload service account or SPIFFE identity does not match the mesh policy principal selector",
                "A recent mesh policy rollout introduced a DENY rule or removed an ALLOW rule for this app-to-app path",
                "Kubernetes Services and endpoints are healthy, but L7 mesh authorization rejects the request",
            ],
            "suggested_checks": [
                f"kubectl logs {pod_name} -n {namespace} -c {sidecar_name}",
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Inspect mesh AuthorizationPolicy/ServerAuthorization/intentions for source principal, namespace, method, and path selectors",
                "Check mesh proxy access logs for RBAC denied or HTTP 403 responses on the failing route",
                "Verify this is not Kubernetes NetworkPolicy by testing DNS and TCP reachability separately from the HTTP request",
            ],
        }
