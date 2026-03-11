from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ServiceEndpointsEmptyRule(FailureRule):
    """
    Detects Services that exist but have no ready endpoints.

    Signals:
    - Service object exists
    - Associated Endpoints/EndpointSlice contain no ready addresses
    - Pod experiences readiness or connectivity failures

    Interpretation:
    The Service selector does not match any ready Pods, or all matching
    Pods are not Ready. As a result, the Service has no endpoints and
    traffic routed through the Service cannot reach a backend.

    Scope:
    - Kubernetes Service routing layer
    - Deterministic (object-state based)
    - Common during rollout failures or readiness probe failures

    Exclusions:
    - Services intentionally created without selectors
    - ExternalName Services
    """

    name = "ServiceEndpointsEmpty"
    category = "Networking"
    priority = 45

    requires = {
        "objects": ["service"],
        "context": ["timeline"],
    }

    optional_objects = ["endpoints", "endpointslice"]

    deterministic = True

    blocks = [
        "DNSResolutionFailure",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        objects = context.get("objects", {})
        services = objects.get("service", {})
        endpoints = objects.get("endpoints", {})
        endpoint_slices = objects.get("endpointslice", {})

        if not services:
            return False

        # Pick first service (consistent with other rules)
        svc_name = next(iter(services))
        svc = services.get(svc_name, {})

        spec = svc.get("spec", {})

        # Ignore ExternalName services
        if spec.get("type") == "ExternalName":
            return False

        # Ignore selector-less services
        if not spec.get("selector"):
            return False

        # ---- Check Endpoints object ----
        if svc_name in endpoints:
            ep = endpoints[svc_name]
            subsets = ep.get("subsets", [])

            if not subsets:
                return True

            for s in subsets:
                addresses = s.get("addresses", [])
                if addresses:
                    return False

            return True

        # ---- Check EndpointSlice objects ----
        for slice_obj in endpoint_slices.values():
            labels = slice_obj.get("metadata", {}).get("labels", {})
            if labels.get("kubernetes.io/service-name") != svc_name:
                continue

            endpoints_list = slice_obj.get("endpoints", [])

            ready = any(
                ep.get("conditions", {}).get("ready") is True
                for ep in endpoints_list
            )

            if not ready:
                return True

        # ---- fallback heuristic from events ----
        if timeline_has_pattern(
            timeline,
            [{"reason": "Unhealthy"}],
        ):
            return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        services = objects.get("service", {})

        svc_name = next(iter(services), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_PRESENT",
                    message=f"Service '{svc_name}' exists",
                    role="service_context",
                ),
                Cause(
                    code="SERVICE_ENDPOINTS_EMPTY",
                    message=f"Service '{svc_name}' has no ready endpoints",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="SERVICE_ROUTING_FAILURE",
                    message="Traffic cannot reach backend Pods through the Service",
                    role="service_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": f"Service '{svc_name}' has no ready endpoints",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                f"Service {svc_name} exists",
                "No ready endpoints found for the Service",
            ],
            "object_evidence": {
                f"service:{svc_name}": [
                    "Service selector matches no ready Pods",
                ]
            },
            "likely_causes": [
                "No Pods match the Service selector",
                "Matching Pods are not Ready",
                "Readiness probes failing",
                "Pods crashed or not yet started",
            ],
            "suggested_checks": [
                f"kubectl describe service {svc_name}",
                f"kubectl get endpoints {svc_name}",
                f"kubectl get pods -l <service-selector>",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }