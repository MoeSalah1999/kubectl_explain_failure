from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CSINodeTopologyLabelsMissingRule(FailureRule):
    """
    Detects CSI provisioning failures caused by missing topology
    information on Node or CSINode objects.

    Real-world behavior:
    - Topology-aware CSI drivers (EBS, PD, Azure Disk, Portworx, etc.)
      require topology information to satisfy topology-aware
      provisioning and scheduling.
    - Missing topology labels typically result in PVCs remaining Pending.
    - External provisioners commonly emit errors such as:
          "no topology key found on CSINode"
          "failed to get topology from CSINode"
          "topology labels missing from Node"
          "no available topology found"
          "error generating accessibility requirements"
    - This is a deterministic infrastructure configuration issue.

    Exclusions:
    - StorageClass not found
    - Provisioner unavailable
    - VolumeAttachment failures
    - Capacity exhaustion
    - AccessMode incompatibilities
    """

    name = "CSINodeTopologyLabelsMissing"
    category = "Storage"
    severity = "High"
    priority = 84
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "node",
            "csinode",
            "pvc",
            "storageclass",
        ],
    }

    WINDOW_MINUTES = 30

    TOPOLOGY_ERROR_MARKERS = (
        "no topology key found on csinode",
        "failed to get topology from csinode",
        "missing topology labels",
        "topology labels missing",
        "failed to generate accessibility requirements",
        "no available topology found",
        "topology requirements could not be satisfied",
        "failed to discover topology",
        "error generating accessibility requirements",
        "topology information is not available",
    )

    PROVISIONING_REASONS = {
        "ProvisioningFailed",
        "ExternalProvisioning",
    }

    STANDARD_TOPOLOGY_LABELS = (
        "topology.kubernetes.io/zone",
        "topology.kubernetes.io/region",
        "failure-domain.beta.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/region",
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _ordered_recent_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)

        indexed = list(enumerate(recent))

        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _pvc_name(
        self,
        pod: dict[str, Any],
    ) -> str | None:
        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim")

            if not isinstance(claim, dict):
                continue

            claim_name = claim.get("claimName")

            if claim_name:
                return str(claim_name)

        return None

    def _targets_pod_or_pvc(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        pvc_name: str | None,
    ) -> bool:
        involved = event.get("involvedObject", {})

        if not isinstance(involved, dict):
            return False

        kind = str(involved.get("kind") or "").lower()

        if kind == "pod":
            return involved.get("name") == pod.get("metadata", {}).get("name")

        if kind == "persistentvolumeclaim" and pvc_name:
            return involved.get("name") == pvc_name

        return False

    def _topology_events(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        pvc_name = self._pvc_name(pod)

        matches = []

        for event in self._ordered_recent_events(timeline):
            if not self._targets_pod_or_pvc(
                event,
                pod,
                pvc_name,
            ):
                continue

            if self._reason(event) not in self.PROVISIONING_REASONS:
                continue

            message = self._message(event).lower()

            if any(marker in message for marker in self.TOPOLOGY_ERROR_MARKERS):
                matches.append(event)

        return matches

    def _node_missing_labels(
        self,
        node_name: str | None,
        context: dict[str, Any],
    ) -> str | None:
        if not node_name:
            return None

        node = context.get("objects", {}).get("node", {}).get(node_name)

        if not isinstance(node, dict):
            return None

        labels = node.get("metadata", {}).get("labels", {}) or {}

        if any(label in labels for label in self.STANDARD_TOPOLOGY_LABELS):
            return None

        return "Node lacks standard topology " "zone/region labels"

    def _csinode_missing_topology(
        self,
        node_name: str | None,
        context: dict[str, Any],
    ) -> str | None:
        if not node_name:
            return None

        csinode = context.get("objects", {}).get("csinode", {}).get(node_name)

        if not isinstance(csinode, dict):
            return None

        drivers = csinode.get("spec", {}).get("drivers", []) or []

        if not drivers:
            return "CSINode contains no registered CSI drivers"

        for driver in drivers:
            if not isinstance(driver, dict):
                continue

            topology_keys = driver.get("topologyKeys") or []

            if topology_keys:
                return None

        return "CSINode drivers advertise no topologyKeys"

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        topology_events = self._topology_events(
            pod,
            timeline,
        )

        if not topology_events:
            return None

        node_name = pod.get("spec", {}).get("nodeName")

        node_signal = self._node_missing_labels(
            node_name,
            context,
        )

        csinode_signal = self._csinode_missing_topology(
            node_name,
            context,
        )

        latest = topology_events[-1]

        object_evidence: dict[str, list[str]] = {}

        if node_name and node_signal:
            object_evidence[f"node:{node_name}"] = [node_signal]

        if node_name and csinode_signal:
            object_evidence[f"csinode:{node_name}"] = [csinode_signal]

        pvc_name = self._pvc_name(pod)

        if pvc_name:
            object_evidence[f"pvc:{pvc_name}"] = [self._message(latest)]

        return {
            "node_name": node_name,
            "pvc_name": pvc_name,
            "message": self._message(latest),
            "count": sum(self._occurrences(e) for e in topology_events),
            "node_signal": node_signal,
            "csinode_signal": csinode_signal,
            "object_evidence": object_evidence,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(
                pod,
                timeline,
                context,
            )
            is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError(
                "CSINodeTopologyLabelsMissing " "requires Timeline context"
            )

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "CSINodeTopologyLabelsMissing " "explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_TOPOLOGY_REQUIRED",
                    message=(
                        "CSI driver requires topology " "information for provisioning"
                    ),
                    role="runtime_context",
                ),
                Cause(
                    code="CSINODE_TOPOLOGY_LABELS_MISSING",
                    message=("Node or CSINode topology " "information is missing"),
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_PROVISIONING_FAILED",
                    message=(
                        "Volume provisioning cannot " "determine an eligible topology"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            (f"Pod {namespace}/{pod_name} is " "waiting for volume provisioning"),
            ("Provisioner reported topology error: " f"{candidate['message']}"),
            (
                f"Observed {candidate['count']} "
                "topology-related provisioning failures"
            ),
        ]

        if candidate["node_name"]:
            evidence.append(f"Provisioning targeted node " f"{candidate['node_name']}")

        if candidate["node_signal"]:
            evidence.append(candidate["node_signal"])

        if candidate["csinode_signal"]:
            evidence.append(candidate["csinode_signal"])

        return {
            "rule": self.name,
            "root_cause": (
                "CSI topology labels or topology keys "
                "are missing from the target node"
            ),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": (candidate["object_evidence"]),
            "likely_causes": [
                "Node missing topology.kubernetes.io/zone label",
                "Node missing topology.kubernetes.io/region label",
                "Cloud controller failed to populate topology labels",
                "CSI node plugin registered without topology support",
                "CSINode topologyKeys field is empty",
                "Topology labels were removed from the node",
            ],
            "suggested_checks": [
                (f"kubectl describe pod " f"{pod_name} -n {namespace}"),
                (
                    f"kubectl describe node " f"{candidate['node_name']}"
                    if candidate["node_name"]
                    else "kubectl get nodes --show-labels"
                ),
                (
                    f"kubectl get csinode " f"{candidate['node_name']} -o yaml"
                    if candidate["node_name"]
                    else "kubectl get csinode"
                ),
                (
                    "Verify topology.kubernetes.io/zone "
                    "and region labels exist on the node"
                ),
                ("Verify CSINode " "spec.drivers[*].topologyKeys"),
                ("Check external-provisioner logs " "for topology errors"),
                ("Check CSI node plugin logs " "for topology registration failures"),
            ],
        }
