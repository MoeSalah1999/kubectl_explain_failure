from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class InitContainerImagePullThenMainCrashRule(FailureRule):
    """
    Detects a temporal failure chain where an init container fails to pull
    its image and later the main container enters CrashLoopBackOff.

    Signals:
    - ImagePullBackOff or ErrImagePull events for an init container
    - Subsequent CrashLoopBackOff events for the main container
    - Timeline shows ordered pattern across container lifecycle

    Interpretation:
    An init container failed to fetch its image during startup. After
    eventual recovery or retry, the main container starts but repeatedly
    crashes because initialization steps were incomplete.

    Scope:
    - Multi-container lifecycle
    - Temporal correlation across init and main containers

    Exclusions:
    - Pods without init containers
    - Crash loops unrelated to init image pulls
    """

    name = "InitContainerImagePullThenMainCrash"
    category = "Temporal"
    priority = 75

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "ImagePullBackOff",
        "ImagePullError",
        "CrashLoopBackOff",
    ]

    def _has_init_container(self, pod) -> bool:
        return bool(pod.get("spec", {}).get("initContainers"))

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not self._has_init_container(pod):
            return False

        # Temporal ordering:
        # init image pull failure -> later crash loop
        return timeline_has_pattern(
            timeline,
            [
                {"reason": "ErrImagePull"},
                {"reason": "CrashLoopBackOff"},
            ],
        ) or timeline_has_pattern(
            timeline,
            [
                {"reason": "ImagePullBackOff"},
                {"reason": "CrashLoopBackOff"},
            ],
        )

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        root_msg = "Init container image pull failure caused incomplete initialization before main container start"

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_CONTAINER_PRESENT",
                    message="Pod defines one or more init containers",
                    role="workload_context",
                ),
                Cause(
                    code="INIT_IMAGE_PULL_FAILURE",
                    message="Init container failed to pull required image",
                    role="container_symptom",
                ),
                Cause(
                    code="INCOMPLETE_INITIALIZATION",
                    message=root_msg,
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="MAIN_CONTAINER_CRASH_LOOP",
                    message="Main container repeatedly crashes after startup",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_msg,
            "confidence": 0.86,
            "causes": chain,
            "evidence": [
                "Event: ErrImagePull or ImagePullBackOff for init container",
                "Event: CrashLoopBackOff for main container",
                "Temporal ordering detected between init failure and main crash",
            ],
            "likely_causes": [
                "Init container image missing or private registry auth failure",
                "Network connectivity to container registry unavailable",
                "Incorrect image tag for init container",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl get pod {pod_name} -o yaml",
                f"kubectl logs {pod_name} -c <init-container-name>",
            ],
            "blocking": False,
        }