from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class ReadWriteOnceMultiNodeConflictRule(FailureRule):
    """
    Detects scheduling failures caused by ReadWriteOnce (RWO) volumes already
    mounted on another node.

    Signals:
    - FailedScheduling events referencing volume attachment
    - Volume reported as already attached to another node
    - PVC access mode is ReadWriteOnce

    Interpretation:
    A PersistentVolume with ReadWriteOnce access mode is already mounted
    by a Pod on another node. Kubernetes prevents scheduling this Pod
    because the volume cannot be attached simultaneously to multiple nodes.

    Scope:
    - Storage attachment and scheduling interaction
    - Deterministic (volume access-mode constraint)
    - Common in StatefulSets or rapid Pod rescheduling

    Exclusions:
    - Multi-node capable volumes (RWX)
    - Volumes that support multi-attach
    """

    name = "ReadWriteOnceMultiNodeConflict"
    category = "PersistentVolumeClaim"
    priority = 55

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "FailedScheduling",
        "FailedMount",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})

        if not pvc_objs:
            return False

        pvc = next(iter(pvc_objs.values()))
        access_modes = pvc.get("spec", {}).get("accessModes", [])

        # Only relevant for RWO volumes
        if "ReadWriteOnce" not in access_modes:
            return False

        # Look for scheduler failure patterns
        if timeline_has_pattern(
            timeline,
            [
                {"reason": "FailedScheduling"},
            ],
        ):
            # Look for multi-attach indicators in event messages
            for e in events:
                msg = (e.get("message") or "").lower()
                if (
                    "multi-attach" in msg
                    or "already attached" in msg
                    or "exclusively attached" in msg
                ):
                    return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})

        pvc_name = next(iter(pvc_objs), "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_RWO_VOLUME",
                    message=f"PVC '{pvc_name}' uses ReadWriteOnce access mode",
                    role="volume_context",
                ),
                Cause(
                    code="RWO_ALREADY_ATTACHED",
                    message="Volume already attached to another node",
                    blocking=True,
                    role="volume_root",
                ),
                Cause(
                    code="POD_CANNOT_SCHEDULE_WITH_VOLUME",
                    message="Scheduler cannot place Pod because volume cannot attach to multiple nodes",
                    role="volume_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")

        return {
            "root_cause": "ReadWriteOnce volume already attached to another node",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} accessMode=ReadWriteOnce",
                "Scheduler event indicates volume already attached",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": [
                    "Volume uses ReadWriteOnce access mode",
                    "Multi-node attachment attempted",
                ]
            },
            "likely_causes": [
                "Another Pod is already using the volume on a different node",
                "StatefulSet Pod rescheduled while previous Pod still terminating",
                "Storage backend does not support multi-node attachment",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "kubectl get pods -A -o wide | grep <volume>",
                f"kubectl describe pod {pod_name}",
            ],
            "blocking": True,
        }
