from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class SecretStoreProviderUnavailableRule(FailureRule):
    """
    Detects workloads blocked because an external secret provider is unavailable.

    Real-world behavior:
    - External Secrets Operator, Vault Agent/CSI, and Secrets Store CSI are often
      just the Kubernetes-facing sync layer
    - the durable root cause can be a provider outage: Vault sealed/unreachable,
      AWS Secrets Manager throttling/5xx, Azure Key Vault service unavailable,
      GCP Secret Manager deadline exceeded, or provider DNS/TLS transport failure
    - pods then surface missing Secret, missing key, CreateContainerConfigError,
      or FailedMount symptoms even though the manifest is otherwise correct
    """

    name = "SecretStoreProviderUnavailable"
    category = "Compound"
    severity = "High"
    priority = 82
    deterministic = True

    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "externalsecret",
            "secretstore",
            "clustersecretstore",
            "secretproviderclass",
            "secretproviderclasspodstatus",
            "secret",
        ],
    }

    blocks = [
        "ExternalSecretsSyncFailure",
        "SecretNotFound",
        "SecretKeyMissing",
        "ConfigDependencyMissingChain",
        "ContainerCreateConfigError",
        "FailedMount",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    WINDOW_MINUTES = 30
    MAX_PROVIDER_TO_POD_GAP = timedelta(minutes=15)
    CACHE_KEY = "_secret_store_provider_unavailable_candidate"

    PROVIDER_MARKERS = (
        "vault",
        "hashicorp vault",
        "aws secrets manager",
        "secretsmanager",
        "secrets manager",
        "azure key vault",
        "keyvault",
        "key vault",
        "gcp secret manager",
        "google secret manager",
        "secretmanager.googleapis.com",
        "secret provider",
        "provider",
    )

    OUTAGE_MARKERS = (
        "service unavailable",
        "temporarily unavailable",
        "provider unavailable",
        "unavailable",
        "internal server error",
        "bad gateway",
        "gateway timeout",
        "503",
        "502",
        "504",
        "context deadline exceeded",
        "deadline exceeded",
        "timed out",
        "timeout",
        "i/o timeout",
        "connection refused",
        "connection reset",
        "connection reset by peer",
        "no such host",
        "temporary failure in name resolution",
        "dns",
        "tls handshake timeout",
        "remote error: tls",
        "vault is sealed",
        "vault sealed",
        "sealed",
        "no active vault node",
        "leader not found",
        "throttlingexception",
        "throttling",
        "rate exceeded",
        "too many requests",
        "resourceexhausted",
        "quota exceeded",
    )

    SYNC_LAYER_MARKERS = (
        "externalsecret",
        "external secret",
        "external-secrets",
        "external-secrets.io",
        "secretstore",
        "clustersecretstore",
        "secret provider class",
        "secretproviderclass",
        "secrets-store.csi.k8s.io",
        "secrets-store-csi-driver",
        "csi-secrets-store",
        "failed to sync",
        "failed to refresh",
        "failed to fetch",
        "failed to mount secrets store objects",
        "provider error",
    )

    POD_SECRET_FAILURE_MARKERS = (
        "secret",
        "couldn't find key",
        "not found",
        "failedmount",
        "failed mount",
        "failed to setup volume",
        "mountvolume.setup failed",
        "createcontainerconfigerror",
        "references non-existent secret key",
        "secretproviderclass",
        "secrets-store.csi.k8s.io",
        "failed to mount secrets store objects",
    )

    SECRET_NOT_FOUND_RE = re.compile(r'secret "([^"]+)" not found', re.IGNORECASE)
    SECRET_KEY_RE = re.compile(
        r'couldn\'t find key "?([^"\s]+)"? in Secret (?:(?:[^/\s]+)/)?([^\s",]+)',
        re.IGNORECASE,
    )
    NONEXISTENT_SECRET_KEY_RE = re.compile(
        r"references non-existent secret key:\s*([^\s\",]+)",
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
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
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

    def _object_name(self, obj: dict[str, Any], fallback: str) -> str:
        return str(obj.get("metadata", {}).get("name") or fallback)

    def _object_namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _collect_secret_refs(self, pod: dict[str, Any]) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}
        spec = pod.get("spec", {}) or {}

        def add(name: str | None, surface: str, optional: bool = False) -> None:
            if optional or not name:
                return
            refs.setdefault(str(name), [])
            if surface not in refs[str(name)]:
                refs[str(name)].append(surface)

        for volume in spec.get("volumes", []) or []:
            volume_name = str(volume.get("name") or "<volume>")
            secret = volume.get("secret") or {}
            add(
                secret.get("secretName"),
                f"Referenced by secret volume '{volume_name}'",
                bool(secret.get("optional")),
            )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_secret = source.get("secret") or {}
                add(
                    projected_secret.get("name"),
                    f"Referenced by projected volume '{volume_name}'",
                    bool(projected_secret.get("optional")),
                )

        for container_group in ("initContainers", "containers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = str(container.get("name") or "<container>")
                for env in container.get("env", []) or []:
                    secret_ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}
                    add(
                        secret_ref.get("name"),
                        f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        bool(secret_ref.get("optional")),
                    )
                for env_from in container.get("envFrom", []) or []:
                    secret_ref = env_from.get("secretRef") or {}
                    add(
                        secret_ref.get("name"),
                        f"Referenced by envFrom in container '{container_name}'",
                        bool(secret_ref.get("optional")),
                    )

        return refs

    def _collect_secret_provider_classes(
        self, pod: dict[str, Any]
    ) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}
        for volume in (pod.get("spec", {}) or {}).get("volumes", []) or []:
            csi = volume.get("csi") or {}
            if csi.get("driver") != "secrets-store.csi.k8s.io":
                continue
            attrs = csi.get("volumeAttributes", {}) or {}
            spc_name = attrs.get("secretProviderClass")
            if not spc_name:
                continue
            refs.setdefault(str(spc_name), [])
            refs[str(spc_name)].append(
                f"Referenced by Secrets Store CSI volume '{volume.get('name', '<volume>')}'"
            )
        return refs

    def _provider_from_text(self, text: str) -> str | None:
        lowered = text.lower()
        if (
            "aws" in lowered
            or "secretsmanager" in lowered
            or "secrets manager" in lowered
        ):
            return "AWS Secrets Manager"
        if "azure" in lowered or "keyvault" in lowered or "key vault" in lowered:
            return "Azure Key Vault"
        if (
            "gcp" in lowered
            or "google" in lowered
            or "secretmanager.googleapis.com" in lowered
        ):
            return "GCP Secret Manager"
        if "vault" in lowered:
            return "Vault"
        if "provider" in lowered:
            return "external secret provider"
        return None

    def _provider_from_object(self, obj: dict[str, Any]) -> str | None:
        spec = obj.get("spec", {}) or {}
        provider = spec.get("provider")
        if isinstance(provider, str):
            return self._provider_from_text(provider) or provider
        if isinstance(provider, dict):
            return self._provider_from_text(
                str(provider.keys())
            ) or self._provider_from_text(str(provider))
        parameters = spec.get("parameters")
        if isinstance(parameters, dict):
            return self._provider_from_text(str(parameters))
        return self._provider_from_text(str(obj))

    def _is_provider_outage_text(self, text: str) -> bool:
        lowered = text.lower()
        has_provider = any(marker in lowered for marker in self.PROVIDER_MARKERS)
        has_outage = any(marker in lowered for marker in self.OUTAGE_MARKERS)
        has_sync_layer = any(marker in lowered for marker in self.SYNC_LAYER_MARKERS)
        return has_provider and has_outage and (has_sync_layer or has_provider)

    def _condition_text(self, obj: dict[str, Any]) -> str:
        bits: list[str] = []
        for condition in obj.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue
            bits.append(
                " ".join(
                    str(condition.get(key) or "")
                    for key in ("type", "status", "reason", "message")
                )
            )
        return " ".join(bits)

    def _object_outage_detail(self, obj: dict[str, Any]) -> str | None:
        text = " ".join(
            [
                self._condition_text(obj),
                str(obj.get("status", {}) or {}),
                str(obj.get("spec", {}) or {}),
            ]
        )
        if not self._is_provider_outage_text(text):
            return None

        for condition in obj.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue
            status = str(condition.get("status") or "")
            reason = str(condition.get("reason") or "")
            message = str(condition.get("message") or "")
            combined = f"{reason} {message}"
            if status == "False" or self._is_provider_outage_text(combined):
                return f"{condition.get('type', 'Condition')}={status} reason={reason}: {message}".strip(
                    ": "
                )
        return "Secret provider reports outage or transport unavailability"

    def _external_object_context(
        self,
        context: dict[str, Any],
        namespace: str,
    ) -> dict[str, Any]:
        objects = context.get("objects", {}) or {}
        signals: list[str] = []
        object_evidence: dict[str, list[str]] = {}
        target_secret_names: set[str] = set()
        spc_names: set[str] = set()
        external_names: set[str] = set()
        providers: set[str] = set()

        for fallback, obj in (objects.get("externalsecret", {}) or {}).items():
            if not isinstance(obj, dict):
                continue
            if self._object_namespace(obj) != namespace:
                continue
            name = self._object_name(obj, str(fallback))
            external_names.add(name)
            target = obj.get("spec", {}).get("target", {}) or {}
            target_secret_names.add(str(target.get("name") or name))
            provider = self._provider_from_object(obj)
            if provider:
                providers.add(provider)
            detail = self._object_outage_detail(obj)
            if detail:
                signals.append(f"ExternalSecret '{name}' reports {detail}")
                object_evidence[f"externalsecret:{name}"] = [detail]

        for kind in ("secretstore", "clustersecretstore"):
            for fallback, obj in (objects.get(kind, {}) or {}).items():
                if not isinstance(obj, dict):
                    continue
                if kind == "secretstore" and self._object_namespace(obj) != namespace:
                    continue
                name = self._object_name(obj, str(fallback))
                external_names.add(name)
                provider = self._provider_from_object(obj)
                if provider:
                    providers.add(provider)
                detail = self._object_outage_detail(obj)
                if detail:
                    signals.append(f"{kind.title()} '{name}' reports {detail}")
                    object_evidence[f"{kind}:{name}"] = [detail]

        for fallback, obj in (objects.get("secretproviderclass", {}) or {}).items():
            if not isinstance(obj, dict):
                continue
            if self._object_namespace(obj) != namespace:
                continue
            name = self._object_name(obj, str(fallback))
            spc_names.add(name)
            external_names.add(name)
            provider = self._provider_from_object(obj)
            if provider:
                providers.add(provider)
            for entry in obj.get("spec", {}).get("secretObjects", []) or []:
                if isinstance(entry, dict) and entry.get("secretName"):
                    target_secret_names.add(str(entry["secretName"]))

        for fallback, obj in (
            objects.get("secretproviderclasspodstatus", {}) or {}
        ).items():
            if not isinstance(obj, dict):
                continue
            if self._object_namespace(obj) != namespace:
                continue
            name = self._object_name(obj, str(fallback))
            spc_name = str(obj.get("status", {}).get("secretProviderClassName") or name)
            spc_names.add(spc_name)
            external_names.add(spc_name)
            provider = self._provider_from_object(obj)
            if provider:
                providers.add(provider)
            detail = self._object_outage_detail(obj)
            if detail:
                signals.append(
                    f"SecretProviderClassPodStatus '{name}' reports {detail}"
                )
                object_evidence[f"secretproviderclasspodstatus:{name}"] = [detail]

        return {
            "signals": signals,
            "object_evidence": object_evidence,
            "target_secret_names": target_secret_names,
            "spc_names": spc_names,
            "external_names": external_names,
            "providers": providers,
        }

    def _is_provider_outage_event(
        self,
        event: dict[str, Any],
        target_names: set[str],
        external_names: set[str],
    ) -> bool:
        text = " ".join(
            [self._reason(event), self._message(event), self._source_component(event)]
        )
        if not self._is_provider_outage_text(text):
            return False
        if not target_names and not external_names:
            return True
        lowered = text.lower()
        return any(
            name.lower() in lowered for name in target_names | external_names
        ) or any(marker in lowered for marker in self.SYNC_LAYER_MARKERS)

    def _extract_secret_from_pod_failure(self, message: str) -> str | None:
        secret_missing = self.SECRET_NOT_FOUND_RE.search(message)
        if secret_missing:
            return str(secret_missing.group(1))
        key_missing = self.SECRET_KEY_RE.search(message)
        if key_missing:
            return str(key_missing.group(2))
        return None

    def _is_pod_secret_failure(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        target_secret_names: set[str],
        spc_names: set[str],
    ) -> bool:
        if not self._event_involves_pod(event, pod):
            return False
        text = f"{self._reason(event)} {self._message(event)}".lower()
        if not any(marker in text for marker in self.POD_SECRET_FAILURE_MARKERS):
            return False
        extracted = self._extract_secret_from_pod_failure(self._message(event))
        if extracted and target_secret_names:
            return extracted in target_secret_names
        if any(name.lower() in text for name in target_secret_names | spc_names):
            return True
        if self.NONEXISTENT_SECRET_KEY_RE.search(self._message(event)):
            return bool(target_secret_names)
        return False

    def _status_waiting_on_secret(self, pod: dict[str, Any]) -> tuple[bool, str]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            reason = str(waiting.get("reason") or "")
            message = str(waiting.get("message") or "")
            if reason in {"CreateContainerConfigError", "ContainerCreating"}:
                return True, str(status.get("name") or "<container>")
            if "secret" in message.lower() or "secretproviderclass" in message.lower():
                return True, str(status.get("name") or "<container>")
        return False, "<container>"

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        namespace, pod_name = self._pod_key(pod)
        object_context = self._external_object_context(context, namespace)
        target_secret_names = set(object_context["target_secret_names"])
        spc_names = set(object_context["spc_names"])
        external_names = set(object_context["external_names"])
        provider_names = set(object_context["providers"])

        pod_secret_refs = self._collect_secret_refs(pod)
        pod_spc_refs = self._collect_secret_provider_classes(pod)
        if not target_secret_names:
            target_secret_names.update(pod_secret_refs)
        if not spc_names:
            spc_names.update(pod_spc_refs)

        if not (
            set(pod_secret_refs) & target_secret_names or set(pod_spc_refs) & spc_names
        ):
            return None

        ordered = self._ordered_recent_events(timeline)
        provider_events = [
            event
            for event in ordered
            if self._is_provider_outage_event(
                event,
                target_secret_names | spc_names,
                external_names,
            )
        ]
        pod_failures = [
            event
            for event in ordered
            if self._is_pod_secret_failure(event, pod, target_secret_names, spc_names)
        ]

        if not provider_events and not object_context["signals"]:
            return None

        waiting_on_secret, waiting_container = self._status_waiting_on_secret(pod)
        if not pod_failures and not waiting_on_secret:
            return None

        sequences: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for provider_event in provider_events:
            for pod_event in pod_failures:
                if pod_event is provider_event:
                    sequences.append((provider_event, pod_event))
                    break
            if sequences and sequences[-1][0] is provider_event:
                continue

            provider_end = self._event_end(provider_event) or self._event_time(
                provider_event
            )
            if provider_end is None:
                continue
            for pod_event in pod_failures:
                pod_time = self._event_time(pod_event)
                if pod_time is None or pod_time < provider_end:
                    continue
                if pod_time - provider_end > self.MAX_PROVIDER_TO_POD_GAP:
                    break
                sequences.append((provider_event, pod_event))
                break

        if provider_events and pod_failures and not sequences:
            return None

        provider_occurrences = sum(
            self._occurrences(event) for event in provider_events
        )
        representative_provider = (
            max(
                provider_events,
                key=lambda event: (self._occurrences(event), self._message(event)),
            )
            if provider_events
            else None
        )
        representative_pod_failure = (
            max(
                pod_failures,
                key=lambda event: (self._occurrences(event), self._message(event)),
            )
            if pod_failures
            else None
        )
        if representative_provider:
            provider = self._provider_from_text(
                f"{self._reason(representative_provider)} {self._message(representative_provider)} {self._source_component(representative_provider)}"
            )
            if provider:
                provider_names.add(provider)

        duration_seconds = timeline.duration_between(
            lambda event: self._is_provider_outage_event(
                event,
                target_secret_names | spc_names,
                external_names,
            )
        )

        return {
            "pod_name": pod_name,
            "namespace": namespace,
            "target_secret_names": sorted(target_secret_names),
            "spc_names": sorted(spc_names),
            "external_names": sorted(external_names),
            "provider_names": sorted(provider_names) or ["external secret provider"],
            "provider_occurrences": provider_occurrences,
            "representative_provider_message": (
                self._message(representative_provider).strip()
                if representative_provider
                else object_context["signals"][0]
            ),
            "representative_pod_failure_message": (
                self._message(representative_pod_failure).strip()
                if representative_pod_failure
                else ""
            ),
            "object_signal_evidence": object_context["signals"],
            "object_evidence": object_context["object_evidence"],
            "sequence_count": len(sequences),
            "waiting_on_secret": waiting_on_secret,
            "waiting_container": waiting_container,
            "duration_seconds": max(0.0, duration_seconds),
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
                "SecretStoreProviderUnavailable explain() called without match"
            )

        pod_name = candidate["pod_name"]
        namespace = candidate["namespace"]
        provider_display = ", ".join(candidate["provider_names"])
        target_display = (
            ", ".join(candidate["target_secret_names"])
            or ", ".join(candidate["spc_names"])
            or "secret material"
        )

        evidence = [
            f"Pod {namespace}/{pod_name} depends on external secret provider material: {target_display}",
            f"Provider availability failure is associated with {provider_display}",
            f"Representative provider outage: {candidate['representative_provider_message']}",
        ]
        if candidate["provider_occurrences"]:
            evidence.append(
                f"Observed {candidate['provider_occurrences']} provider outage occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )
        if candidate["representative_pod_failure_message"]:
            evidence.append(
                f"Representative pod secret dependency symptom: {candidate['representative_pod_failure_message']}"
            )
        if candidate["sequence_count"]:
            evidence.append(
                f"Timeline links provider outage to pod secret/mount failure in {candidate['sequence_count']} sequence(s)"
            )
        if candidate["waiting_on_secret"]:
            evidence.append(
                f"Container '{candidate['waiting_container']}' is waiting on externally backed secret material"
            )
        if candidate["duration_seconds"] > 0:
            evidence.append(
                f"Provider outage signals persisted for {candidate['duration_seconds'] / 60.0:.1f} minutes"
            )
        evidence.extend(candidate["object_signal_evidence"])

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod startup depends on externally backed secret material while the provider is unavailable"
            ],
            "timeline:secret_store_provider": [
                "Provider outage occurred before or during the pod secret dependency failure"
            ],
        }
        for secret_name in candidate["target_secret_names"]:
            object_evidence[f"secret:{secret_name}"] = [
                "Secret material depends on an unavailable external provider"
            ]
        for spc_name in candidate["spc_names"]:
            object_evidence[f"secretproviderclass:{spc_name}"] = [
                "Secrets Store CSI provider class depends on an unavailable provider"
            ]
        for key, items in candidate["object_evidence"].items():
            object_evidence.setdefault(key, []).extend(items)

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_USES_EXTERNAL_SECRET_PROVIDER",
                    message=f"Pod references secret material backed by {provider_display}",
                    role="configuration_context",
                ),
                Cause(
                    code="SECRET_STORE_PROVIDER_UNAVAILABLE",
                    message=f"{provider_display} is unavailable or returning outage-class errors",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="SECRET_SYNC_OR_MOUNT_CANNOT_COMPLETE",
                    message="External secret sync or Secrets Store CSI mount cannot publish required Kubernetes secret material",
                    role="configuration_intermediate",
                ),
                Cause(
                    code="POD_SECRET_DEPENDENCY_BLOCKED",
                    message="Pod startup remains blocked because required secret-backed configuration is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "External secret provider is unavailable",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Vault is sealed, has no active leader, or is unreachable from the cluster",
                "AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager is returning 5xx, timeout, throttling, or quota errors",
                "Provider DNS, TLS, proxy, or private endpoint connectivity is unavailable",
                "Secrets Store CSI or External Secrets controller cannot reach the external provider endpoint",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get secretstore,clustersecretstore,externalsecret -A",
                "kubectl get secretproviderclass,secretproviderclasspodstatus -A",
                "Inspect external-secrets and secrets-store-csi-driver logs for provider outage errors",
                "Check Vault health or cloud secret-manager service health, quotas, private endpoints, DNS, and TLS connectivity",
            ],
        }
