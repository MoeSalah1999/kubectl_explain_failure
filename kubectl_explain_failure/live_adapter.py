from __future__ import annotations

import json
import subprocess
from typing import Any


class LiveIntrospectionError(RuntimeError):
    pass


def _resource_for_owner_kind(kind: str) -> str | None:
    mapping = {
        "ReplicaSet": "replicaset",
        "Deployment": "deployment",
        "StatefulSet": "statefulset",
        "DaemonSet": "daemonset",
    }
    return mapping.get(kind)


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

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=max(1, timeout_seconds),
    )

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
    kind: str,
    name: str | None,
    *,
    namespace: str | None,
    kube_context: str | None,
    kubeconfig: str | None,
    timeout_seconds: int,
    warnings: list[str],
    extra_args: list[str] | None = None,
) -> dict[str, Any] | None:
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
        warnings.append(str(exc))
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


def _extract_secret_names(pod: dict[str, Any]) -> list[str]:
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


def fetch_live_snapshot(
    *,
    pod_name: str,
    namespace: str,
    kube_context: str | None = None,
    kubeconfig: str | None = None,
    timeout_seconds: int = 10,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str]]:
    warnings: list[str] = []

    pod = _kubectl_get_json(
        "pod",
        pod_name,
        namespace=namespace,
        kube_context=kube_context,
        kubeconfig=kubeconfig,
        timeout_seconds=timeout_seconds,
    )

    events_selector = f"involvedObject.kind=Pod,involvedObject.name={pod_name}"
    events_raw = _safe_get_json(
        "events",
        None,
        namespace=namespace,
        kube_context=kube_context,
        kubeconfig=kubeconfig,
        timeout_seconds=timeout_seconds,
        warnings=warnings,
        extra_args=[f"--field-selector={events_selector}"],
    )

    events: list[dict[str, Any]] = []
    if isinstance(events_raw, dict):
        events = (
            events_raw.get("items", [])
            if events_raw.get("kind") == "List"
            else [events_raw]
        )

    context: dict[str, Any] = {"objects": {}}

    # PVC -> PV -> StorageClass
    for pvc_name in _extract_pvc_names(pod):
        pvc = _safe_get_json(
            "pvc",
            pvc_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
        )
        _add_object(context, "pvc", pvc)

        if pvc:
            pv_name = pvc.get("spec", {}).get("volumeName")
            if pv_name:
                pv = _safe_get_json(
                    "pv",
                    pv_name,
                    namespace=None,
                    kube_context=kube_context,
                    kubeconfig=kubeconfig,
                    timeout_seconds=timeout_seconds,
                    warnings=warnings,
                )
                _add_object(context, "pv", pv)

            sc_name = pvc.get("spec", {}).get("storageClassName")
            if sc_name:
                sc = _safe_get_json(
                    "storageclass",
                    sc_name,
                    namespace=None,
                    kube_context=kube_context,
                    kubeconfig=kubeconfig,
                    timeout_seconds=timeout_seconds,
                    warnings=warnings,
                )
                _add_object(context, "storageclass", sc)

    # Node
    node_name = pod.get("spec", {}).get("nodeName")
    if node_name:
        node = _safe_get_json(
            "node",
            node_name,
            namespace=None,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
        )
        _add_object(context, "node", node)
        if node:
            # Legacy compatibility for existing node rules
            context["node"] = node

    # Owner controllers
    owners = pod.get("metadata", {}).get("ownerReferences", [])
    for owner in owners:
        if not isinstance(owner, dict):
            continue
        owner_kind = owner.get("kind")
        owner_name = owner.get("name")
        if not owner_kind or not owner_name:
            continue

        resource = _resource_for_owner_kind(owner_kind)
        if not resource:
            continue

        owner_obj = _safe_get_json(
            resource,
            owner_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
        )
        _add_object(context, resource, owner_obj)

        if owner_obj and "owner" not in context:
            context["owner"] = owner_obj

    # ServiceAccount
    service_account = pod.get("spec", {}).get("serviceAccountName")
    if service_account:
        sa_obj = _safe_get_json(
            "serviceaccount",
            service_account,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
        )
        _add_object(context, "serviceaccount", sa_obj)

    # Secrets
    for secret_name in _extract_secret_names(pod):
        secret_obj = _safe_get_json(
            "secret",
            secret_name,
            namespace=namespace,
            kube_context=kube_context,
            kubeconfig=kubeconfig,
            timeout_seconds=timeout_seconds,
            warnings=warnings,
        )
        _add_object(context, "secret", secret_obj)

    return pod, events, context, warnings
