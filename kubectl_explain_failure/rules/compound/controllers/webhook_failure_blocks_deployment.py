from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class WebhookFailureBlocksDeploymentRule(FailureRule):
    """
    Detects Deployment rollouts blocked by repeated admission webhook failures.

    Signals:
    - Deployment has fewer available replicas than desired or reports rollout stall
    - Timeline contains admission webhook FailedCreate/FailedAdmission errors
    - Failures occur during controller-driven pod creation attempts

    Interpretation:
    The Deployment controller is trying to create new Pods, but admission
    webhooks are rejecting or failing those create requests. The rollout
    cannot make progress, so the Deployment remains degraded.

    Scope:
    - Controller + admission interaction
    - Non-deterministic summary (object state + event correlation)
    - Summarizes rollout impact when more specific admission root causes
      are not available
    """

    name = "WebhookFailureBlocksDeployment"
    category = "Compound"
    priority = 40
    deterministic = False
    blocks = [
        "DeploymentProgressDeadlineExceeded",
        "DeploymentReplicaMismatch",
        "ReplicaSetCreateFailure",
    ]
    requires = {
        "objects": ["deployment"],
        "context": ["timeline"],
    }
    phases = ["Pending", "Running"]

    WEBHOOK_MARKERS = (
        "webhook",
        "gatekeeper",
        "kyverno",
    )

    CONTROLLER_SOURCES = {
        "replicaset-controller",
        "deployment-controller",
    }

    def _source_component(self, event) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component", "")).lower()
        return str(source or "").lower()

    def _deployment_stalled(self, deployments) -> bool:
        for dep in deployments.values():
            status = dep.get("status", {})
            desired = status.get("replicas", 0)
            available = status.get("availableReplicas", 0)

            if desired > 0 and available < desired:
                return True

            for cond in status.get("conditions", []):
                if (
                    cond.get("type") == "Progressing"
                    and cond.get("reason") == "ProgressDeadlineExceeded"
                ):
                    return True

        return False

    def matches(self, pod, events, context) -> bool:
        deployments = context.get("objects", {}).get("deployment", {})
        timeline = context.get("timeline")
        if not deployments or not timeline:
            return False

        if not self._deployment_stalled(deployments):
            return False

        webhook_failures = []
        for e in timeline.raw_events:
            reason = str(e.get("reason", "")).lower()
            msg = str(e.get("message", "")).lower()
            source = self._source_component(e)

            if reason not in {"failedcreate", "failed", "failedadmission"}:
                continue

            if source and source not in self.CONTROLLER_SOURCES:
                continue

            if any(marker in msg for marker in self.WEBHOOK_MARKERS):
                webhook_failures.append(e)

        return len(webhook_failures) >= 2

    def explain(self, pod, events, context):
        deployments = context.get("objects", {}).get("deployment", {})
        dep_name, dep = next(iter(deployments.items()))
        status = dep.get("status", {})
        desired = status.get("replicas", 0)
        available = status.get("availableReplicas", 0)

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_ROLLOUT_ACTIVE",
                    message=f"Deployment '{dep_name}' is attempting to create replicas",
                    role="controller_context",
                ),
                Cause(
                    code="ADMISSION_WEBHOOK_FAILURE",
                    message="Admission webhook failures are blocking new pod creation",
                    role="admission_root",
                    blocking=True,
                ),
                Cause(
                    code="DEPLOYMENT_PROGRESS_BLOCKED",
                    message="Deployment cannot reach desired replica availability",
                    role="controller_intermediate",
                ),
                Cause(
                    code="DEPLOYMENT_DEGRADED",
                    message=f"Deployment remains below target availability ({available}/{desired})",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Deployment rollout blocked by admission webhook failures",
            "confidence": 0.84,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Deployment '{dep_name}' has {available}/{desired} available replicas",
                "Repeated admission webhook failure events observed during controller pod creation",
            ],
            "object_evidence": {
                f"deployment:{dep_name}": [
                    f"Deployment availability below target ({available}/{desired})"
                ]
            },
            "likely_causes": [
                "Mutating or validating webhook is rejecting pod creations",
                "Webhook connectivity or TLS issues are blocking admission",
                "Policy engine instability is preventing rollout progress",
            ],
            "suggested_checks": [
                f"kubectl describe deployment {dep_name}",
                "kubectl get mutatingwebhookconfigurations",
                "kubectl get validatingwebhookconfigurations",
                "Review ReplicaSet and controller events for FailedCreate",
            ],
        }
