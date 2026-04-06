from __future__ import annotations

KNOWN_SIDECAR_NAMES = {
    "istio-proxy",
    "linkerd-proxy",
    "consul-connect-envoy",
    "envoy",
    "vault-agent",
    "fluent-bit",
    "promtail",
    "vector",
    "otel-collector",
    "aws-otel-collector",
    "datadog-agent",
    "cloud-sql-proxy",
}

SIDECAR_SUFFIXES = ("-proxy", "-agent", "-sidecar")

INJECTION_ANNOTATION_KEYS = (
    "sidecar.istio.io/status",
    "sidecar.istio.io/inject",
    "linkerd.io/inject",
    "vault.hashicorp.com/agent-inject",
    "consul.hashicorp.com/connect-inject",
)

SIDECAR_IMAGE_MARKERS = (
    "istio/proxyv2",
    "linkerd/proxy",
    "envoyproxy/envoy",
    "consul/connect-envoy",
    "hashicorp/vault",
    "otel/opentelemetry-collector",
    "public.ecr.aws/aws-observability/aws-otel-collector",
    "fluent/fluent-bit",
    "grafana/promtail",
    "timberio/vector",
    "gcr.io/cloud-sql-connectors/cloud-sql-proxy",
    "datadog/agent",
)


def pod_has_sidecar_injection_signal(pod: dict) -> bool:
    annotations = (pod.get("metadata", {}) or {}).get("annotations", {}) or {}
    for key in INJECTION_ANNOTATION_KEYS:
        value = annotations.get(key)
        if value is None:
            continue
        if str(value).strip().lower() not in {"", "false", "disabled"}:
            return True
    return False


def _all_container_specs_by_name(pod: dict) -> dict[str, dict]:
    spec = pod.get("spec", {}) or {}
    containers = (spec.get("containers", []) or []) + (
        spec.get("initContainers", []) or []
    )
    return {
        str(container.get("name")): container
        for container in containers
        if container.get("name")
    }


def is_recognized_sidecar_container(pod: dict, container_name: str) -> bool:
    lowered_name = str(container_name or "").strip().lower()
    if not lowered_name:
        return False

    if lowered_name in KNOWN_SIDECAR_NAMES:
        return True

    if lowered_name.endswith(SIDECAR_SUFFIXES):
        return True

    container_spec = _all_container_specs_by_name(pod).get(container_name, {})
    image = str(container_spec.get("image", "")).lower()
    if any(marker in image for marker in SIDECAR_IMAGE_MARKERS):
        return True

    if pod_has_sidecar_injection_signal(pod) and (
        "proxy" in lowered_name or "agent" in lowered_name
    ):
        return True

    return False


def is_restartable_init_sidecar(pod: dict, container_name: str) -> bool:
    spec = pod.get("spec", {}) or {}
    init_containers = spec.get("initContainers", []) or []

    for container in init_containers:
        if container.get("name") != container_name:
            continue

        if str(container.get("restartPolicy", "")).lower() != "always":
            return False

        return is_recognized_sidecar_container(pod, container_name)

    return False
