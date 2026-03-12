from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class RollingUpdateStuckMidwayRule(FailureRule):
    """
    Detects Deployment rolling updates that stall midway.

    Signals:
    - Deployment rollout in progress
    - New ReplicaSet created
    - Old pods terminating slowly
    - Rollout duration exceeds expected window

    Interpretation:
    The Deployment controller initiated a rolling update but progress
    has stalled. New pods may not be becoming ready or old pods are
    failing to terminate, preventing rollout completion.

    Scope:
    - Deployment controller behavior
    - Temporal rollout progression analysis
    """

    name = "RollingUpdateStuckMidway"
    category = "Compound"
    priority = 85

    requires = {
        "objects": ["deployment", "replicaset"],
        "context": ["timeline"],
    }

    deterministic = False

    blocks = [
        "ReplicaSetUnavailable",
        "DeploymentProgressDeadlineExceeded",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        objects = context.get("objects", {})

        if not timeline:
            return False

        deployments = objects.get("deployment", {})
        replicasets = objects.get("replicaset", {})

        if not deployments or not replicasets:
            return False

        deploy = next(iter(deployments.values()))

        status = deploy.get("status", {})
        spec = deploy.get("spec", {})

        desired = spec.get("replicas", 1)
        updated = status.get("updatedReplicas", 0)
        ready = status.get("readyReplicas", 0)

        # rollout started but not completed
        rollout_in_progress = updated > 0 and ready < desired

        if not rollout_in_progress:
            return False

        # detect rollout-related events
        rollout_signal = timeline_has_pattern(
            timeline,
            [
                {"reason": "ScalingReplicaSet"},
            ],
        )

        if not rollout_signal:
            return False

        # detect slow rollout window
        rollout_duration = timeline.duration_between(
            lambda e: e.get("reason") == "ScalingReplicaSet"
        )

        # 10 minutes threshold heuristic
        if rollout_duration > 600:
            context["stalled_rollout"] = True
            return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        deployments = objects.get("deployment", {})

        deploy_name = next(iter(deployments), "<deployment>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="DEPLOYMENT_ROLLOUT_STARTED",
                    message=f"Deployment '{deploy_name}' initiated rolling update",
                    role="controller_context",
                ),
                Cause(
                    code="ROLLOUT_PROGRESS_STALLED",
                    message="Deployment rollout stalled during rolling update",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="PARTIAL_DEPLOYMENT_UPDATE",
                    message="New pods created but rollout not completing",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": "Deployment rolling update stalled midway",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                f"Deployment {deploy_name} rollout detected",
                "Rolling update events observed",
                "Rollout duration exceeds expected threshold",
            ],
            "object_evidence": {
                f"deployment:{deploy_name}": [
                    "Rolling update initiated but not completed"
                ]
            },
            "likely_causes": [
                "New pods failing readiness checks",
                "Insufficient node capacity for new pods",
                "Image pull or container startup failures",
                "Pod disruption budget preventing old pod termination",
            ],
            "suggested_checks": [
                f"kubectl rollout status deployment {deploy_name}",
                f"kubectl describe deployment {deploy_name}",
                f"kubectl get pods -l app=<label> -o wide",
            ],
            "blocking": True,
        }