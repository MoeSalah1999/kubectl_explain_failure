from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime
from typing import Any, Protocol

from kubectl_explain_failure.engine import normalize_context


class LiveIntrospectionError(RuntimeError):
    pass


class LiveDataProvider(Protocol):
    def get_json(
        self,
        kind: str,
        name: str | None = None,
        *,
        namespace: str | None = None,
        kube_context: str | None = None,
        kubeconfig: str | None = None,
        timeout_seconds: int = 10,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        ...


def _is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, subprocess.TimeoutExpired):
        return True

    msg = str(exc).lower()
    retry_markers = (
        "timeout",
        "timed out",
        "temporarily unavailable",
        "connection refused",
        "unable to connect to the server",
        "tls handshake timeout",
        "i/o timeout",
        "eof",
        "too many requests",
        "service unavailable",
    )
    return any(marker in msg for marker in retry_markers)


class KubectlLiveDataProvider:
    def __init__(
        self,
        *,
        max_retries: int = 1,
        retry_backoff_seconds: float = 0.25,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if retry_backoff_seconds <= 0:
            raise ValueError("retry_backoff_seconds must be > 0")

        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

    def get_json(
        self,
        kind: str,
        name: str | None = None,
        *,
        namespace: str | None = None,
        kube_context: str | None = None,
        kubeconfig: str | None = None,
        timeout_seconds: int = 10,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        last_exc: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                return _kubectl_get_json(
                    kind,
                    name,
                    namespace=namespace,
                    kube_context=kube_context,
                    kubeconfig=kubeconfig,
                    timeout_seconds=timeout_seconds,
                    extra_args=extra_args,
                )
            except (LiveIntrospectionError, subprocess.TimeoutExpired) as exc:
                last_exc = exc
                if attempt >= self.max_retries or not _is_retryable_error(exc):
                    raise
                sleep_seconds = self.retry_backoff_seconds * (2**attempt)
                time.sleep(sleep_seconds)

        if last_exc:
            raise last_exc
        raise LiveIntrospectionError("live data provider failed unexpectedly")


def _resource_for_owner_kind(kind: str) -> str | None:
    mapping = {
        "ReplicaSet": "replicaset",
        "Deployment": "deployment",
        "StatefulSet": "statefulset",
        "DaemonSet": "daemonset",
    }
    return mapping.get(kind)


def _classify_fetch_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return "timeout"

    msg = str(exc).lower()
    if "forbidden" in msg or "cannot list resource" in msg or "cannot get resource" in msg:
        return "rbac_forbidden"
    if "not found" in msg or "notfound" in msg:
        return "not_found"
    return "other"


def _kubectl_get_json(
    kind: str,
    name: str | None = None,
    *,
    namespace: str | None = None,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
    timeout_seconds: int = 10,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    cmd = ["kubectl", "get", kind]
    if name:
        cmd.append(name)

    if namespace:
        cmd += ["-n", namespace]

    if kube_context:
        cmd += ["--context", kube_context]

    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]

    if extra_args:
        cmd += list(extra_args)

    cmd += ["--request-timeout", f"{timeout_seconds}s", "-o", "json"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(1, timeout_seconds),
        )
    except FileNotFoundError as exc:
        raise LiveIntrospectionError(
            "kubectl binary was not found in PATH"
        ) from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise LiveIntrospectionError(
            f"kubectl get {kind}{' ' + name if name else ''} failed: {stderr}"
        )

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LiveIntrospectionError(
            f"kubectl output for {kind}{' ' + name if name else ''} is not valid JSON"
        ) from exc


def _safe_get_json(
    provider: LiveDataProvider,
    kind: str,
    name: str | None,
    *,
    namespace: str | None,
    kube_context: str | None,
    kubeconfig: str | None,
    timeout_seconds: int,
    warnings: list[str],
    missing_resources: list[dict[str, Any]],
    extra_args: list[str] | None = None,
) -> dict[str, Any] | None:
    try:
        return provider.get_json(
            kind,
            name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            extra_args=extra_args,
        )
    except (LiveIntrospectionError, subprocess.TimeoutExpired) as exc:
        warnings.append(str(exc))
        missing_resources.append(
            {
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "reason": _classify_fetch_error(exc),
                "error": str(exc),
            }
        )
        return None


def _add_object(context: dict[str, Any], kind: str, obj: dict[str, Any] | None) -> None:
    if not obj:
        return
    name = obj.get("metadata", {}).get("name")
    if not name:
        return
    context.setdefault("objects", {})
    context["objects"].setdefault(kind, {})
    context["objects"][kind][name] = obj


def _extract_pvc_names(pod: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for v in pod.get("spec", {}).get("volumes", []):
        claim_name = (
            v.get("persistentVolumeClaim", {}).get("claimName")
            if isinstance(v, dict)
            else None
        )
        if claim_name:
            out.append(claim_name)
    return sorted(set(out))


def _extract_secret_names_from_pod(pod: dict[str, Any]) -> list[str]:
    names: set[str] = set()

    spec = pod.get("spec", {})

    for ref in spec.get("imagePullSecrets", []):
        name = ref.get("name") if isinstance(ref, dict) else None
        if name:
            names.add(name)

    for vol in spec.get("volumes", []):
        if not isinstance(vol, dict):
            continue
        secret_name = vol.get("secret", {}).get("secretName")
        if secret_name:
            names.add(secret_name)

        for src in vol.get("projected", {}).get("sources", []):
            if not isinstance(src, dict):
                continue
            projected_secret_name = src.get("secret", {}).get("name")
            if projected_secret_name:
                names.add(projected_secret_name)

    containers = []
    containers.extend(spec.get("containers", []))
    containers.extend(spec.get("initContainers", []))

    for c in containers:
        if not isinstance(c, dict):
            continue

        for env in c.get("env", []):
            if not isinstance(env, dict):
                continue
            env_secret = env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
            if env_secret:
                names.add(env_secret)

        for env_from in c.get("envFrom", []):
            if not isinstance(env_from, dict):
                continue
            env_from_secret = env_from.get("secretRef", {}).get("name")
            if env_from_secret:
                names.add(env_from_secret)

    return sorted(names)


def _extract_secret_names_from_serviceaccount(sa_obj: dict[str, Any] | None) -> list[str]:
    if not sa_obj:
        return []

    names: set[str] = set()

    for ref in sa_obj.get("secrets", []):
        if not isinstance(ref, dict):
            continue
        name = ref.get("name")
        if name:
            names.add(name)

    for ref in sa_obj.get("imagePullSecrets", []):
        if not isinstance(ref, dict):
            continue
        name = ref.get("name")
        if name:
            names.add(name)

    return sorted(names)


def _event_timestamp_value(event: dict[str, Any]) -> datetime | None:
    ts = (
        event.get("eventTime")
        or event.get("lastTimestamp")
        or event.get("firstTimestamp")
        or event.get("metadata", {}).get("creationTimestamp")
    )
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _sort_and_limit_events(
    events: list[dict[str, Any]],
    *,
    event_limit: int,
) -> list[dict[str, Any]]:
    if event_limit <= 0:
        return []

    ordered = sorted(
        events,
        key=lambda e: (_event_timestamp_value(e) is None, _event_timestamp_value(e)),
    )

    if len(ordered) <= event_limit:
        return ordered

    return ordered[-event_limit:]


def _resolve_owner_chain(
    provider: LiveDataProvider,
    *,
    start_obj: dict[str, Any],
    namespace: str,
    kube_context: str | None,
    kubeconfig: str | None,
    timeout_seconds: int,
    warnings: list[str],
    missing_resources: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    resolved: list[tuple[str, dict[str, Any]]] = []
    visited: set[tuple[str, str]] = set()

    current = start_obj
    max_depth = 5

    for _ in range(max_depth):
        refs = current.get("metadata", {}).get("ownerReferences", [])
        if not isinstance(refs, list) or not refs:
            break

        next_ref = None
        for ref in refs:
            if isinstance(ref, dict) and ref.get("kind") and ref.get("name"):
                next_ref = ref
                break
        if not next_ref:
            break

        owner_kind = next_ref["kind"]
        owner_name = next_ref["name"]
        resource = _resource_for_owner_kind(owner_kind)
        if not resource:
            break

        key = (resource, owner_name)
        if key in visited:
            break
        visited.add(key)

        owner_obj = _safe_get_json(
            provider,
            resource,
            owner_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
            missing_resources=missing_resources,
        )
        if not owner_obj:
            break

        resolved.append((resource, owner_obj))
        current = owner_obj

    return resolved


def fetch_live_snapshot(
    *,
    pod_name: str,
    namespace: str,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
    timeout_seconds: int = 10,
    event_limit: int = 200,
    event_chunk_size: int = 200,
    retry_count: int = 1,
    retry_backoff_seconds: float = 0.25,
    provider: LiveDataProvider | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str], dict[str, Any]]:
    provider = provider or KubectlLiveDataProvider(
        max_retries=retry_count,
        retry_backoff_seconds=retry_backoff_seconds,
    )

    warnings: list[str] = []
    missing_resources: list[dict[str, Any]] = []

    pod = provider.get_json(
        "pod",
        pod_name,
        namespace=namespace,
        kube_context=kube_context,
        kubeconfig=kubeconfig,
        timeout_seconds=timeout_seconds,
    )

    events_selector = f"involvedObject.kind=Pod,involvedObject.name={pod_name}"
    events_raw = _safe_get_json(
        provider,
        "events",
        None,
        namespace=namespace,
        kube_context=kube_context,
        kubeconfig=kubeconfig,
        timeout_seconds=timeout_seconds,
        warnings=warnings,
        missing_resources=missing_resources,
        extra_args=[
            f"--field-selector={events_selector}",
            f"--chunk-size={max(1, event_chunk_size)}",
            "--sort-by=.metadata.creationTimestamp",
        ],
    )

    events: list[dict[str, Any]] = []
    if isinstance(events_raw, dict):
        events = (
            events_raw.get("items", [])
            if events_raw.get("kind") == "List"
            else [events_raw]
        )
    events = _sort_and_limit_events(events, event_limit=event_limit)

    context: dict[str, Any] = {"objects": {}}

    for pvc_name in _extract_pvc_names(pod):
        pvc = _safe_get_json(
            provider,
            "pvc",
            pvc_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
            missing_resources=missing_resources,
        )
        _add_object(context, "pvc", pvc)

        if pvc:
            pv_name = pvc.get("spec", {}).get("volumeName")
            if pv_name:
                pv = _safe_get_json(
                    provider,
                    "pv",
                    pv_name,
                    namespace=None,
                    kube_context=kube_context,
                    kubeconfig=kubeconfig,
                    timeout_seconds=timeout_seconds,
                    warnings=warnings,
                    missing_resources=missing_resources,
                )
                _add_object(context, "pv", pv)

            sc_name = pvc.get("spec", {}).get("storageClassName")
            if sc_name:
                sc = _safe_get_json(
                    provider,
                    "storageclass",
                    sc_name,
                    namespace=None,
                    kube_context=kube_context,
                    kubeconfig=kubeconfig,
                    timeout_seconds=timeout_seconds,
                    warnings=warnings,
                    missing_resources=missing_resources,
                )
                _add_object(context, "storageclass", sc)

    node_name = pod.get("spec", {}).get("nodeName")
    if node_name:
        node = _safe_get_json(
            provider,
            "node",
            node_name,
            namespace=None,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
            missing_resources=missing_resources,
        )
        _add_object(context, "node", node)
        if node:
            context["node"] = node

    owner_chain = _resolve_owner_chain(
        provider,
        start_obj=pod,
        namespace=namespace,
        kube_context=kube_context,
        kubeconfig=kubeconfig,
        timeout_seconds=timeout_seconds,
        warnings=warnings,
        missing_resources=missing_resources,
    )
    for resource, owner_obj in owner_chain:
        _add_object(context, resource, owner_obj)
    if owner_chain:
        context["owner"] = owner_chain[-1][1]

    sa_obj: dict[str, Any] | None = None
    service_account = pod.get("spec", {}).get("serviceAccountName")
    if service_account:
        sa_obj = _safe_get_json(
            provider,
            "serviceaccount",
            service_account,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
            missing_resources=missing_resources,
        )
        _add_object(context, "serviceaccount", sa_obj)

    secret_names = set(_extract_secret_names_from_pod(pod))
    secret_names.update(_extract_secret_names_from_serviceaccount(sa_obj))

    for secret_name in sorted(secret_names):
        secret_obj = _safe_get_json(
            provider,
            "secret",
            secret_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
            missing_resources=missing_resources,
        )
        _add_object(context, "secret", secret_obj)

    rbac_missing = [m for m in missing_resources if m.get("reason") == "rbac_forbidden"]
    missing_kinds = sorted({m.get("kind") for m in missing_resources if m.get("kind")})

    missing_kinds_by_reason: dict[str, list[str]] = {}
    for reason in ("rbac_forbidden", "not_found", "timeout", "other"):
        kinds = sorted(
            {
                m.get("kind")
                for m in missing_resources
                if m.get("reason") == reason and m.get("kind")
            }
        )
        if kinds:
            missing_kinds_by_reason[reason] = kinds

    fetched_object_counts = {
        kind: len(mapping)
        for kind, mapping in context.get("objects", {}).items()
        if isinstance(mapping, dict)
    }

    live_metadata = {
        "event_count": len(events),
        "fetch_warning_count": len(warnings),
        "fetched_object_counts": fetched_object_counts,
        "fetched_object_total": sum(fetched_object_counts.values()),
        "missing_kinds": missing_kinds,
        "missing_kinds_by_reason": missing_kinds_by_reason,
        "missing_resources": missing_resources,
        "missing_due_to_rbac": rbac_missing,
        "completeness": {
            "missing_total": len(missing_resources),
            "rbac_missing_total": len(rbac_missing),
        },
    }

    return pod, events, normalize_context(context), warnings, live_metadata
