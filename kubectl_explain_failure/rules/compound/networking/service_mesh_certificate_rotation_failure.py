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


class ServiceMeshCertificateRotationFailureRule(FailureRule):
    """
    Detects service-mesh mTLS certificate expiry or rotation failures.

    Real-world behavior:
    - mesh proxies depend on short-lived workload identity certificates
      delivered through SDS/identity APIs such as Istio Agent, Linkerd Identity,
      or Consul Connect
    - expiry, CSR signing, CA bundle, or secret propagation failures usually
      surface as sidecar readiness failures first
    - application probes or requests fail after the sidecar cannot obtain or
      rotate valid mTLS material

    This is intentionally more specific than generic service-mesh sidecar
    blocking or control-plane-unavailable diagnoses.
    """

    name = "ServiceMeshCertificateRotationFailure"
    category = "Compound"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "secret",
            "certificate",
            "certificaterequest",
            "deployment",
            "pod",
        ],
    }

    blocks = [
        "ServiceMeshControlPlaneUnavailable",
        "ServiceMeshSidecarNetworkBlock",
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
        "ProbeTimeout",
        "ProbeEndpointConnectionRefused",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 30
    MAX_CERT_TO_APP_GAP = timedelta(minutes=6)
    MIN_CERT_OCCURRENCES = 2
    CACHE_KEY = "_service_mesh_certificate_rotation_failure_candidate"

    MESH_SIDECAR_NAMES = {
        "istio-proxy",
        "linkerd-proxy",
        "consul-connect-envoy",
        "envoy",
    }

    MESH_CERT_COMPONENTS = (
        "istio-agent",
        "istiod",
        "pilot",
        "citadel",
        "linkerd-identity",
        "linkerd-proxy",
        "consul-connect",
        "consul-controller",
        "cert-manager",
    )

    CERT_ROOT_MARKERS = (
        "x509: certificate has expired",
        "certificate has expired",
        "certificate is not yet valid",
        "not yet valid",
        "failed to fetch workload certificate",
        "failed to generate workload certificate",
        "failed to rotate certificate",
        "certificate rotation failed",
        "rotation failed",
        "failed rotating",
        "workload certificate",
        "identity certificate",
        "failed to sign csr",
        "csr signing failed",
        "failed to create csr",
        "failed to warm certificate",
        "secret is not supplied",
        "secret not found",
        "sds",
        "spiffe",
        "ca bundle",
        "trust bundle",
        "tls: failed to verify certificate",
    )

    CERT_FAILURE_WORDS = (
        "expired",
        "not yet valid",
        "failed",
        "failure",
        "denied",
        "timeout",
        "unavailable",
        "invalid",
        "stale",
        "missing",
        "not found",
    )

    APP_IMPACT_MARKERS = (
        "readiness probe failed",
        "liveness probe failed",
        "startup probe failed",
        "http probe failed with statuscode: 503",
        "http probe failed with statuscode: 500",
        "upstream connect error",
        "disconnect/reset before headers",
        "tls handshake error",
        "certificate required",
        "connection reset",
        "service unavailable",
        "remote error: tls",
    )

    OBJECT_CERT_FAILURE_MARKERS = (
        "expired",
        "renewal failed",
        "renewalfailure",
        "issuing",
        "failed",
        "not after",
        "notafter",
        "does not exist",
        "private key",
        "csr",
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

    def _is_mesh_certificate_message(self, text: str) -> bool:
        lowered = text.lower()
        if any(marker in lowered for marker in self.CERT_ROOT_MARKERS):
            if any(word in lowered for word in self.CERT_FAILURE_WORDS):
                return True
            return any(
                token in lowered
                for token in ("workload certificate", "identity certificate", "sds")
            )

        certificate_context = any(
            token in lowered
            for token in ("certificate", "cert", "csr", "sds", "spiffe", "identity")
        )
        failed = any(word in lowered for word in self.CERT_FAILURE_WORDS)
        mesh_context = any(
            token in lowered
            for token in (
                "istio",
                "linkerd",
                "consul",
                "envoy",
                "workload",
                "mtls",
                "identity",
                "trust bundle",
            )
        )
        return certificate_context and failed and mesh_context

    def _is_certificate_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        sidecar_names: set[str],
        *,
        assume_single_sidecar: bool,
    ) -> bool:
        message = self._message(event)
        reason = self._reason(event)
        source = self._source_component(event).lower()
        combined = f"{reason} {message}"

        if not self._is_mesh_certificate_message(combined):
            return False

        if self._event_involves_pod(event, pod):
            if not sidecar_names:
                return True
            return any(
                self._container_event_match(
                    event,
                    sidecar_name,
                    assume_single_container=assume_single_sidecar,
                )
                for sidecar_name in sidecar_names
            )

        lowered = combined.lower()
        if any(component in source for component in self.MESH_CERT_COMPONENTS):
            return True
        return any(component in lowered for component in self.MESH_CERT_COMPONENTS)

    def _is_application_impact_event(
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

    def _object_name(self, obj: dict[str, Any], fallback: str) -> str:
        return str(obj.get("metadata", {}).get("name") or fallback)

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _object_text(self, obj: dict[str, Any]) -> str:
        parts: list[str] = []
        for section in ("metadata", "status", "spec", "type"):
            value = obj.get(section)
            if isinstance(value, dict):
                parts.append(str(value))
            elif isinstance(value, str):
                parts.append(value)
        return " ".join(parts).lower()

    def _certificate_object_signals(
        self,
        context: dict[str, Any],
        reference_time: datetime | None,
    ) -> tuple[list[str], dict[str, list[str]]]:
        objects = context.get("objects", {}) or {}
        evidence: list[str] = []
        object_evidence: dict[str, list[str]] = {}

        for kind in ("certificate", "certificaterequest"):
            for fallback, obj in (objects.get(kind, {}) or {}).items():
                if not isinstance(obj, dict):
                    continue
                name = self._object_name(obj, str(fallback))
                text = self._object_text(obj)
                if not any(
                    marker in text for marker in self.OBJECT_CERT_FAILURE_MARKERS
                ):
                    continue

                conditions = obj.get("status", {}).get("conditions", []) or []
                condition_bits = []
                for condition in conditions:
                    if not isinstance(condition, dict):
                        continue
                    status = str(condition.get("status") or "")
                    reason = str(condition.get("reason") or "")
                    message = str(condition.get("message") or "")
                    if status == "False" or any(
                        marker in f"{reason} {message}".lower()
                        for marker in self.OBJECT_CERT_FAILURE_MARKERS
                    ):
                        condition_bits.append(
                            f"{condition.get('type', 'Condition')}={status} reason={reason}".strip()
                        )

                detail = (
                    "; ".join(condition_bits[:2])
                    or "Certificate object reports renewal or issuance failure"
                )
                evidence.append(f"{kind.title()} '{name}' reports {detail}")
                object_evidence[f"{kind}:{name}"] = [detail]

        for fallback, obj in (objects.get("secret", {}) or {}).items():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {}) or {}
            name = self._object_name(obj, str(fallback))
            annotations = metadata.get("annotations", {}) or {}
            labels = metadata.get("labels", {}) or {}
            text = " ".join(
                [
                    str(obj.get("type") or ""),
                    str(annotations),
                    str(labels),
                ]
            ).lower()
            if not any(
                token in text
                for token in ("tls", "certificate", "cert-manager", "istio", "linkerd")
            ):
                continue

            expiry_raw = (
                annotations.get("cert-manager.io/expiry-date")
                or annotations.get("certificate.kubernetes.io/not-after")
                or annotations.get("notAfter")
                or annotations.get("not-after")
            )
            expiry = self._parse_timestamp(expiry_raw)
            if expiry and reference_time and expiry <= reference_time:
                detail = f"TLS Secret expired at {expiry_raw}"
                evidence.append(f"Secret '{name}' contains expired mesh TLS material")
                object_evidence[f"secret:{name}"] = [detail]

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

        certificate_events = [
            event
            for event in ordered
            if self._is_certificate_event(
                event,
                pod,
                sidecar_names,
                assume_single_sidecar=assume_single_sidecar,
            )
        ]
        certificate_occurrences = sum(
            self._occurrences(event) for event in certificate_events
        )
        if (
            len(certificate_events) < self.MIN_CERT_OCCURRENCES
            and certificate_occurrences < self.MIN_CERT_OCCURRENCES
        ):
            return None

        reference_time = self._event_time(ordered[-1])
        object_signal_evidence, object_evidence = self._certificate_object_signals(
            context,
            reference_time,
        )

        impacted_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for cert_event in certificate_events:
            cert_time = self._event_time(cert_event)
            if cert_time is None:
                continue
            for event in ordered:
                impact_time = self._event_time(event)
                if impact_time is None or impact_time < cert_time:
                    continue
                if impact_time - cert_time > self.MAX_CERT_TO_APP_GAP:
                    break
                if self._is_application_impact_event(
                    event,
                    pod,
                    primary_names,
                    assume_single_primary=assume_single_primary,
                ):
                    impacted_pairs.append((cert_event, event))
                    break

        sidecar_unready = any(
            not bool(status.get("ready", False)) for status in sidecars
        )
        if not impacted_pairs and not sidecar_unready and not object_signal_evidence:
            return None

        duration_seconds = timeline.duration_between(
            lambda event: self._is_certificate_event(
                event,
                pod,
                sidecar_names,
                assume_single_sidecar=assume_single_sidecar,
            )
        )

        representative_cert = max(
            certificate_events,
            key=lambda event: (self._occurrences(event), self._message(event)),
        )
        representative_impact = (
            max(
                (pair[1] for pair in impacted_pairs),
                key=lambda event: (self._occurrences(event), self._message(event)),
            )
            if impacted_pairs
            else None
        )

        return {
            "sidecar": sidecars[0],
            "certificate_events": certificate_events,
            "certificate_occurrences": certificate_occurrences,
            "representative_cert_message": self._message(representative_cert).strip(),
            "representative_impact_message": (
                self._message(representative_impact).strip()
                if representative_impact
                else None
            ),
            "impact_pairs": impacted_pairs,
            "sidecar_unready": sidecar_unready,
            "duration_seconds": max(0.0, duration_seconds),
            "object_signal_evidence": object_signal_evidence,
            "object_evidence": object_evidence,
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
                "ServiceMeshCertificateRotationFailure explain() called without match"
            )

        metadata = pod.get("metadata", {}) or {}
        pod_name = str(metadata.get("name") or "<unknown>")
        namespace = str(metadata.get("namespace") or "default")
        sidecar_name = str(candidate["sidecar"].get("name") or "<sidecar>")
        occurrence_count = int(candidate["certificate_occurrences"])
        duration_minutes = candidate["duration_seconds"] / 60.0

        evidence = [
            f"Pod {namespace}/{pod_name} uses service-mesh sidecar '{sidecar_name}' for mTLS",
            f"Observed {occurrence_count} mesh certificate rotation/expiry failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            f"Representative certificate failure: {candidate['representative_cert_message']}",
        ]
        if candidate["sidecar_unready"]:
            evidence.append(
                f"Service-mesh sidecar '{sidecar_name}' is Ready=False while certificate material is failing"
            )
        if candidate["representative_impact_message"]:
            evidence.append(
                f"Representative application impact after certificate failure: {candidate['representative_impact_message']}"
            )
        if duration_minutes > 0:
            evidence.append(
                f"Certificate rotation failures persisted for {duration_minutes:.1f} minutes"
            )
        evidence.extend(candidate["object_signal_evidence"])

        object_evidence = {
            f"pod:{pod_name}": [
                "Workload is impacted by service-mesh mTLS certificate rotation failure"
            ],
            f"container:{sidecar_name}": [
                candidate["representative_cert_message"],
            ],
            "timeline:mesh_certificate_rotation": [
                f"{occurrence_count} certificate failure occurrence(s) in the recent timeline"
            ],
        }
        if candidate["representative_impact_message"]:
            primary_statuses = self._primary_statuses(pod)
            primary_name = (
                str(primary_statuses[0].get("name"))
                if primary_statuses
                else "<application>"
            )
            object_evidence[f"container:{primary_name}"] = [
                candidate["representative_impact_message"]
            ]
        for key, items in candidate["object_evidence"].items():
            object_evidence.setdefault(key, []).extend(items)

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_MESH_MTLS_ENABLED",
                    message=f"Pod traffic is mediated by service-mesh sidecar '{sidecar_name}' and mTLS identity",
                    role="network_context",
                ),
                Cause(
                    code="MESH_WORKLOAD_CERTIFICATE_ROTATION_FAILED",
                    message="The mesh cannot issue, rotate, or trust current workload mTLS certificates",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SIDECAR_LACKS_VALID_MTLS_IDENTITY",
                    message=f"Sidecar '{sidecar_name}' cannot establish valid mTLS identity for mesh traffic",
                    role="network_intermediate",
                ),
                Cause(
                    code="APPLICATION_TRAFFIC_FAILS_THROUGH_MESH",
                    message="Application probes or upstream calls fail after mesh certificate material becomes invalid",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Service mesh mTLS certificate rotation failed",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Workload mTLS certificate expired before the sidecar received a renewed certificate",
                "Mesh CA or identity service cannot sign workload CSRs",
                "SDS or secret distribution is serving stale or missing certificate material",
                "Trust bundle or CA bundle rotation is out of sync across the mesh",
            ],
            "suggested_checks": [
                f"kubectl logs {pod_name} -n {namespace} -c {sidecar_name}",
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Inspect mesh identity or CA logs for CSR signing and certificate rotation errors",
                "Check workload certificate NotAfter/NotBefore values and mesh trust bundle freshness",
                "Verify SDS/secret distribution health before restarting application containers",
            ],
        }
