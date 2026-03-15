from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class HeadlessServiceMissingForStatefulSetRule(FailureRule):
    """
    Detects StatefulSets whose governing headless Service is missing
    or incorrectly configured.

    Signals:
    - Pod owned by a StatefulSet
    - StatefulSet specifies spec.serviceName
    - Corresponding Service missing OR not headless (clusterIP != None)

    Interpretation:
    StatefulSets rely on a governing headless Service to provide stable
    network identities for Pods. If the Service is missing or not configured
    as headless, Pod DNS entries cannot be created correctly.

    Scope:
    - StatefulSet controller configuration
    - Deterministic (object-state based)

    Exclusions:
    - Pods not owned by StatefulSets
    - StatefulSets without serviceName
    """

    name = "HeadlessServiceMissingForStatefulSet"
    category = "Controller"
    priority = 60

    requires = {
        "objects": ["statefulset", "service"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "DNSResolutionFailure",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        owners = context.get("owners", [])
        if not owners:
            return False

        # Verify Pod is owned by StatefulSet
        owner = owners[0]
        if owner.get("kind") != "StatefulSet":
            return False

        objects = context.get("objects", {})
        sts_objs = objects.get("statefulset", {})
        services = objects.get("service", {})

        if not sts_objs:
            return False

        sts = next(iter(sts_objs.values()))
        service_name = sts.get("spec", {}).get("serviceName")

        if not service_name:
            return False

        svc = services.get(service_name)

        # Service missing
        if not svc:
            return True

        # Service exists but is not headless
        cluster_ip = svc.get("spec", {}).get("clusterIP")

        if cluster_ip and cluster_ip != "None":
            return True

        # Timeline signal (optional reinforcement)
        if timeline_has_pattern(
            timeline,
            [
                {"reason": "FailedScheduling"},
            ],
        ):
            return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        sts_objs = objects.get("statefulset", {})
        services = objects.get("service", {})

        sts_name = next(iter(sts_objs), "<unknown>")
        sts = sts_objs.get(sts_name, {})

        service_name = sts.get("spec", {}).get("serviceName", "<unknown>")

        svc = services.get(service_name)

        if not svc:
            root_msg = f"Governing Service '{service_name}' for StatefulSet is missing"
            root_code = "STATEFULSET_SERVICE_MISSING"
        else:
            root_msg = f"Service '{service_name}' is not configured as headless"
            root_code = "STATEFULSET_SERVICE_NOT_HEADLESS"

        chain = CausalChain(
            causes=[
                Cause(
                    code="STATEFULSET_PRESENT",
                    message=f"Pod belongs to StatefulSet '{sts_name}'",
                    role="workload_context",
                ),
                Cause(
                    code=root_code,
                    message=root_msg,
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="STATEFULSET_NETWORK_IDENTITY_BROKEN",
                    message="StatefulSet Pods cannot obtain stable DNS identities",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": root_msg,
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} owned by StatefulSet {sts_name}",
                f"StatefulSet expects Service {service_name}",
            ],
            "object_evidence": {
                f"statefulset:{sts_name}": [
                    f"serviceName={service_name}",
                ]
            },
            "likely_causes": [
                "Headless Service not created",
                "Service created with ClusterIP instead of None",
                "Service deleted after StatefulSet creation",
            ],
            "suggested_checks": [
                f"kubectl describe statefulset {sts_name}",
                f"kubectl get svc {service_name}",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }
