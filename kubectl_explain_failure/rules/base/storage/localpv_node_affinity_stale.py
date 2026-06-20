from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class LocalPVNodeAffinityStaleRule(FailureRule):
    """
    Detects Local PersistentVolumes whose nodeAffinity points to nodes that
    no longer exist, have been renamed, or no longer satisfy the PV's
    scheduling constraints.

    Real-world behavior:
    - Local PVs are bound to specific nodes via spec.nodeAffinity.
    - If the referenced node is removed from the cluster, replaced,
      reprovisioned under a new name, or permanently unavailable,
      workloads using the PV become unschedulable.
    - Kubernetes emits scheduling events such as:
        * volume node affinity conflict
        * node(s) had volume node affinity conflict
        * node affinity mismatch
    - The PVC may remain Bound while Pods stay Pending.
    - Common after node replacement, cluster rebuilds, autoscaling,
      bare-metal maintenance, or disaster recovery.

    Exclusions:
    - Generic PVC provisioning failures.
    - StorageClass failures.
    - CSI attachment failures.
    - Temporary node NotReady conditions.
    - Local PV capacity exhaustion.
    """

    name = "LocalPVNodeAffinityStale"
    category = "Storage"
    severity = "High"
    priority = 95
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "objects": [
            "pv",
            "pvc",
        ],
        "optional_objects": [
            "node",
        ],
    }

    blocks = [
        "PVCPending",
        "PVCProvisioningFailed",
        "VolumeNodeAffinityConflict",
    ]

    AFFINITY_CONFLICT_MARKERS = (
        "volume node affinity conflict",
        "had volume node affinity conflict",
        "node affinity conflict",
        "node affinity mismatch",
        "volume affinity",
        "node(s) had volume node affinity conflict",
    )

    LOCAL_PV_MARKERS = (
        "local",
        "kubernetes.io/no-provisioner",
    )

    NODE_LABEL_KEYS = (
        "kubernetes.io/hostname",
        "beta.kubernetes.io/hostname",
    )

    def _all_pvs(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("pv", {}) or {}

    def _all_pvcs(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("pvc", {}) or {}

    def _all_nodes(
        self,
        context: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        return context.get("objects", {}).get("node", {}) or {}

    def _is_local_pv(
        self,
        pv: dict[str, Any],
    ) -> bool:
        spec = pv.get("spec", {}) or {}

        if "local" in spec:
            return True

        storage_class = str(spec.get("storageClassName") or "").lower()

        if any(marker in storage_class for marker in self.LOCAL_PV_MARKERS):
            return True

        annotations = pv.get("metadata", {}).get("annotations", {}) or {}

        provisioner = str(
            annotations.get(
                "volume.kubernetes.io/storage-provisioner",
                "",
            )
        ).lower()

        return provisioner == "kubernetes.io/no-provisioner"

    def _bound_pv_for_pvc(
        self,
        pvc: dict[str, Any],
        pvs: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        volume_name = pvc.get("spec", {}).get("volumeName")

        if volume_name and volume_name in pvs:
            return pvs[volume_name]

        pvc_name = pvc.get("metadata", {}).get("name")
        pvc_ns = pvc.get("metadata", {}).get("namespace", "default")

        for pv in pvs.values():
            claim_ref = pv.get("spec", {}).get("claimRef", {}) or {}

            if (
                claim_ref.get("name") == pvc_name
                and claim_ref.get("namespace", "default") == pvc_ns
            ):
                return pv

        return None

    def _required_hostnames(
        self,
        pv: dict[str, Any],
    ) -> set[str]:
        affinity = pv.get("spec", {}).get("nodeAffinity", {}).get("required", {})

        terms = affinity.get("nodeSelectorTerms", []) or []

        hostnames: set[str] = set()

        for term in terms:
            for expr in term.get("matchExpressions", []) or []:
                key = str(expr.get("key") or "")

                if key not in self.NODE_LABEL_KEYS:
                    continue

                operator = str(expr.get("operator") or "")

                if operator != "In":
                    continue

                for value in expr.get("values", []) or []:
                    if value:
                        hostnames.add(str(value))

        return hostnames

    def _cluster_hostnames(
        self,
        nodes: dict[str, dict[str, Any]],
    ) -> set[str]:
        hostnames: set[str] = set()

        for node_name, node in nodes.items():
            hostnames.add(node_name)

            labels = node.get("metadata", {}).get("labels", {}) or {}

            for key in self.NODE_LABEL_KEYS:
                value = labels.get(key)

                if value:
                    hostnames.add(str(value))

        return hostnames

    def _event_affinity_conflict(
        self,
        events: list[dict[str, Any]],
    ) -> bool:
        for event in events:
            text = (f"{event.get('reason', '')} " f"{event.get('message', '')}").lower()

            if any(marker in text for marker in self.AFFINITY_CONFLICT_MARKERS):
                return True

        return False

    def _find_failure(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], set[str]] | None:
        pvs = self._all_pvs(context)
        pvcs = self._all_pvcs(context)
        nodes = self._all_nodes(context)

        volumes = pod.get("spec", {}).get("volumes", []) or []

        for volume in volumes:
            pvc_ref = volume.get("persistentVolumeClaim")

            if not isinstance(pvc_ref, dict):
                continue

            pvc_name = pvc_ref.get("claimName")

            if not pvc_name:
                continue

            pvc = pvcs.get(pvc_name)

            if not pvc:
                continue

            pv = self._bound_pv_for_pvc(pvc, pvs)

            if not pv:
                continue

            if not self._is_local_pv(pv):
                continue

            required_nodes = self._required_hostnames(pv)

            if not required_nodes:
                continue

            cluster_nodes = self._cluster_hostnames(nodes)

            # Real stale-affinity condition:
            # every node referenced by the PV is gone.
            if cluster_nodes and required_nodes.isdisjoint(cluster_nodes):
                return pv, pvc, required_nodes

            # Event-driven fallback when object graph is incomplete.
            if not nodes and self._event_affinity_conflict(events):
                return pv, pvc, required_nodes

        return None

    def matches(self, pod, events, context) -> bool:
        return (
            self._find_failure(
                pod,
                events,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        match = self._find_failure(
            pod,
            events,
            context,
        )

        if match is None:
            raise ValueError("LocalPVNodeAffinityStale explain() called without match")

        pv, pvc, required_nodes = match

        pv_name = pv.get("metadata", {}).get("name", "<unknown>")

        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        pvc_ns = pvc.get("metadata", {}).get("namespace", "default")

        required_list = sorted(required_nodes)

        chain = CausalChain(
            causes=[
                Cause(
                    code="LOCAL_PV_NODE_AFFINITY_DEFINED",
                    message=(
                        "Local PersistentVolume is restricted " "to specific node(s)"
                    ),
                    role="configuration",
                ),
                Cause(
                    code="LOCAL_PV_NODE_AFFINITY_STALE",
                    message=(
                        "The nodes referenced by the Local PV "
                        "no longer exist in the cluster"
                    ),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CANNOT_SCHEDULE_ON_LOCAL_VOLUME",
                    message=(
                        "Scheduler cannot place the Pod because "
                        "the Local PV affinity cannot be satisfied"
                    ),
                    role="workload_failure",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": (
                "Local PersistentVolume nodeAffinity references "
                "nodes that no longer exist"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": [
                (f"PVC {pvc_ns}/{pvc_name} is bound to " f"Local PV {pv_name}"),
                (f"PV nodeAffinity requires node(s): " f"{', '.join(required_list)}"),
                (
                    "None of the nodes referenced by the Local PV "
                    "exist in the current cluster inventory"
                ),
            ],
            "object_evidence": {
                f"pv:{pv_name}": [
                    (
                        "Local PV nodeAffinity references "
                        f"missing node(s): {', '.join(required_list)}"
                    )
                ],
                f"pvc:{pvc_name}": [f"Bound to Local PV {pv_name}"],
            },
            "likely_causes": [
                "A node hosting the local disk was removed from the cluster",
                "The node was reprovisioned with a different hostname",
                "A cluster rebuild restored PV objects but not the original nodes",
                "Bare-metal maintenance replaced the node without updating Local PV definitions",
                "Disaster recovery restored stale Local PV metadata",
            ],
            "suggested_checks": [
                f"kubectl describe pv {pv_name}",
                f"kubectl describe pvc {pvc_name} -n {pvc_ns}",
                "kubectl get nodes -o wide",
                (
                    "Inspect spec.nodeAffinity on the Local PV "
                    "and verify the referenced hostname still exists"
                ),
                (
                    "If the disk was migrated, recreate or update "
                    "the Local PV with the correct node affinity"
                ),
                "Review scheduler events for volume node affinity conflicts",
            ],
        }
