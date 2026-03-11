from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ServiceNotFoundRule(FailureRule):
    """
    Detects Pod failures caused by referencing a Kubernetes Service
    that does not exist in the namespace.

    Signals:
    - Pod environment variables reference a service-derived variable
    - Referenced service name is not present in the cluster object graph
    - Timeline contains DNS or connection failures consistent with missing service

    Interpretation:
    The Pod expects a Service to exist (often through environment variable
    injection such as <SERVICE>_SERVICE_HOST), but the Service object is
    missing. As a result, the application may fail to resolve or connect
    to the expected endpoint.

    Scope:
    - Kubernetes Service discovery layer
    - Deterministic (object + configuration mismatch)

    Exclusions:
    - DNS failures caused by CoreDNS outages
    - NetworkPolicy blocks
    """

    name = "ServiceNotFound"
    category = "Networking"
    priority = 42

    requires = {
        "objects": ["service"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "DNSResolutionFailure",
    ]

    def _extract_service_refs(self, pod: dict) -> set[str]:
        """
        Extract service-like references from container environment variables.
        Looks for *_SERVICE_HOST or *_SERVICE_PORT variables.
        """
        refs = set()

        containers = pod.get("spec", {}).get("containers", [])

        for c in containers:
            for env in c.get("env", []):
                name = env.get("name", "")

                if name.endswith("_SERVICE_HOST") or name.endswith("_SERVICE_PORT"):
                    svc = name.replace("_SERVICE_HOST", "").replace("_SERVICE_PORT", "")
                    refs.add(svc.lower().replace("_", "-"))

        return refs

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        objects = context.get("objects", {})
        services = objects.get("service", {})

        referenced_services = self._extract_service_refs(pod)

        if not referenced_services:
            return False

        existing_services = {name.lower() for name in services.keys()}

        missing = referenced_services - existing_services
        if not missing:
            return False

        # Look for supporting networking symptoms
        if timeline_has_pattern(
            timeline,
            [
                {"reason": "Failed"},
            ],
        ):
            return True

        # Also accept absence of service as deterministic signal
        return True

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        services = objects.get("service", {})

        referenced_services = self._extract_service_refs(pod)
        existing_services = {name.lower() for name in services.keys()}
        missing_services = sorted(referenced_services - existing_services)

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        svc_name = missing_services[0] if missing_services else "<unknown>"

        chain = CausalChain(
            causes=[
                Cause(
                    code="SERVICE_REFERENCE",
                    message=f"Pod expects Service '{svc_name}' via environment configuration",
                    role="service_context",
                ),
                Cause(
                    code="SERVICE_NOT_FOUND",
                    message=f"Service '{svc_name}' does not exist in the namespace",
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="SERVICE_DISCOVERY_FAILURE",
                    message="Application cannot discover or connect to the expected Service",
                    role="service_symptom",
                ),
            ]
        )

        return {
            "root_cause": f"Referenced Service '{svc_name}' does not exist",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                f"Pod references Service '{svc_name}' through environment variables",
                "Service object not found in namespace",
            ],
            "object_evidence": {
                f"service:{svc_name}": [
                    "Service expected but not present",
                ]
            },
            "likely_causes": [
                "Service was deleted or never created",
                "Application configuration references incorrect service name",
                "Deployment created before Service resource",
            ],
            "suggested_checks": [
                f"kubectl get svc | grep {svc_name}",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }