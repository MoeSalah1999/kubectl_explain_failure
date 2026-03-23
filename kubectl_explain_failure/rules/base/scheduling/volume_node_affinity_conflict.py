from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class VolumeNodeAffinityConflictRule(FailureRule):
    """
    Detects scheduling failures caused by PersistentVolume node affinity conflicts.

    Signals:
    - FailedScheduling events
    - Message indicates volume node affinity conflict

    Interpretation:
    The Pod references a PVC bound to a PV with node affinity,
    but no available nodes satisfy that affinity.

    Scope:
    - Scheduler + storage interaction
    - Deterministic (event-message based)
    """

    name = "VolumeNodeAffinityConflict"
    category = "Scheduling"
    priority = 26
    deterministic = True
    blocks = ["FailedScheduling"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    phases = ["Pending"]

    AFFINITY_MARKERS = (
        "volume node affinity conflict",
        "node(s) had volume node affinity conflict",
    )

    def _referenced_pvc_names(self, pod) -> list[str]:
        pvc_names = []
        volumes = pod.get("spec", {}).get("volumes", [])

        for volume in volumes:
            claim = volume.get("persistentVolumeClaim")
            if claim and claim.get("claimName"):
                pvc_names.append(claim["claimName"])

        return pvc_names

    def _known_pvcs_are_bound(self, context, pvc_names: list[str]) -> bool:
        if not pvc_names:
            return False

        pvc_objects = context.get("objects", {}).get("pvc", {})
        if not pvc_objects:
            return True

        saw_referenced_pvc = False
        for name in pvc_names:
            pvc = pvc_objects.get(name)
            if not pvc:
                continue

            saw_referenced_pvc = True
            if pvc.get("status", {}).get("phase") != "Bound":
                return False

        return True if saw_referenced_pvc else True

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        pvc_names = self._referenced_pvc_names(pod)
        if not pvc_names:
            return False

        if not self._known_pvcs_are_bound(context, pvc_names):
            return False

        for e in timeline.raw_events:
            if e.get("reason") != "FailedScheduling":
                continue

            msg = (e.get("message") or "").lower()

            if any(marker in msg for marker in self.AFFINITY_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        pvc_names = self._referenced_pvc_names(pod)

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_TO_PV",
                    message="PersistentVolumeClaim is bound to a PersistentVolume",
                    role="storage_context",
                ),
                Cause(
                    code="PV_NODE_AFFINITY_CONFLICT",
                    message="PersistentVolume node affinity does not match available nodes",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_VOLUME_AFFINITY",
                    message="Scheduler cannot place Pod due to volume node affinity constraints",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "Scheduler reports volume node affinity conflict",
        ]

        if pvc_names:
            evidence.append(f"PVCs: {', '.join(pvc_names)}")

        return {
            "rule": self.name,
            "root_cause": "Volume node affinity conflict prevents scheduling",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "PersistentVolume node affinity incompatible with node selection"
                ]
            },
            "likely_causes": [
                "PV is restricted to specific availability zones or nodes",
                "Cluster nodes do not satisfy PV node affinity",
                "PVC bound to a PV in a different zone than available nodes",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pv -o yaml",
                "kubectl get nodes --show-labels",
                "Check PV.spec.nodeAffinity configuration",
            ],
        }
