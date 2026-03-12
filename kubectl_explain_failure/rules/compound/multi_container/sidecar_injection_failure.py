from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class SidecarInjectionFailureRule(FailureRule):
    """
    Detects failure scenarios where a mutating webhook was expected
    to inject a sidecar container but the sidecar is missing, leading
    to application instability or CrashLoop.

    Signals:
    - Pod annotations indicate sidecar injection expected
    - Sidecar container absent from Pod spec
    - CrashLoopBackOff events present in timeline

    Interpretation:
    A mutating admission webhook (e.g. service mesh injector)
    failed to inject a required sidecar container. The main
    container then crashes because it expects the sidecar
    (proxy, agent, etc.) to be present.

    Scope:
    - Admission mutation layer
    - Multi-container runtime behavior
    - Compound rule correlating spec + runtime events

    Exclusions:
    - Pods not configured for sidecar injection
    - Pods that successfully contain the expected sidecar
    """

    name = "SidecarInjectionFailure"
    category = "Compound"
    priority = 85

    deterministic = False

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "CrashLoopBackOff",
    ]

    def _sidecar_expected(self, pod) -> bool:
        """
        Detect common sidecar injection annotations.
        """
        annotations = pod.get("metadata", {}).get("annotations", {}) or {}

        injection_keys = [
            "sidecar.istio.io/inject",
            "linkerd.io/inject",
            "consul.hashicorp.com/connect-inject",
        ]

        for key in injection_keys:
            val = annotations.get(key)
            if val and str(val).lower() in ("true", "enabled", "yes"):
                return True

        return False

    def _sidecar_present(self, pod) -> bool:
        """
        Detect presence of common service mesh sidecars.
        """
        containers = pod.get("spec", {}).get("containers", []) or []

        known_sidecars = {
            "istio-proxy",
            "linkerd-proxy",
            "consul-connect-envoy",
            "envoy",
        }

        for c in containers:
            if c.get("name") in known_sidecars:
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not self._sidecar_expected(pod):
            return False

        if self._sidecar_present(pod):
            return False

        # runtime symptom
        if not timeline_has_pattern(timeline, [{"reason": "CrashLoopBackOff"}]):
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        root_msg = "Expected sidecar container was not injected by mutating webhook"

        chain = CausalChain(
            causes=[
                Cause(
                    code="SIDECAR_INJECTION_EXPECTED",
                    message="Pod annotations request automatic sidecar injection",
                    role="admission_context",
                ),
                Cause(
                    code="SIDECAR_CONTAINER_MISSING",
                    message=root_msg,
                    blocking=True,
                    role="configuration_root",
                ),
                Cause(
                    code="APPLICATION_DEPENDENCY_MISSING",
                    message="Application container depends on sidecar functionality",
                    role="workload_context",
                ),
                Cause(
                    code="CONTAINER_CRASH_LOOP",
                    message="Main container repeatedly crashes due to missing sidecar",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_msg,
            "confidence": 0.86,
            "causes": chain,
            "evidence": [
                "Pod configured for sidecar injection",
                "Expected sidecar container missing from Pod spec",
                "Event: CrashLoopBackOff",
            ],
            "likely_causes": [
                "Mutating webhook unavailable",
                "Webhook configuration failure",
                "Admission controller timeout",
                "Sidecar injector namespace selector mismatch",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get mutatingwebhookconfigurations",
                "kubectl logs -n istio-system deploy/istiod",
            ],
            "blocking": False,
        }