from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CNINetworkAttachmentDefinitionMissingRule(FailureRule):
    """
    Detects Multus secondary-network failures caused by a missing
    NetworkAttachmentDefinition referenced by a Pod.

    Real-world interpretation:
    - the Pod has been scheduled and kubelet is creating the sandbox
    - Multus reads k8s.v1.cni.cncf.io/networks from the Pod
    - one referenced NetworkAttachmentDefinition cannot be found
    - sandbox networking is blocked before containers can start

    Exclusions:
    - default CNI config missing on the node
    - IPAM/address pool exhaustion
    - container runtime connectivity failures
    - old missing-NAD events followed by a successful container start
    """

    name = "CNINetworkAttachmentDefinitionMissing"
    category = "Networking"
    severity = "High"
    priority = 68
    deterministic = True

    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["networkattachmentdefinition"],
    }

    blocks = [
        "CNIPluginFailure",
    ]

    WINDOW_MINUTES = 30

    NETWORKS_ANNOTATION = "k8s.v1.cni.cncf.io/networks"
    SANDBOX_REASONS = {
        "failedcreatepodsandbox",
        "cnipluginfailure",
    }
    MULTUS_OR_NAD_MARKERS = (
        "multus",
        "network-attachment-definition",
        "network attachment definition",
        "network-attachment-definitions.k8s.cni.cncf.io",
        "getnetworkdelegates",
        "tryloadpoddelegates",
        "pod delegates",
    )
    MISSING_MARKERS = (
        "not found",
        "no network-attachment-definition",
        "cannot find a network-attachment-definition",
        "failed getting network",
        "failed to get network",
    )
    EXCLUDED_MARKERS = (
        "cni config uninitialized",
        "no networks found in /etc/cni/net.d",
        "no valid networks found in /etc/cni/net.d",
        "failed to load cni config",
        "network plugin is not ready",
        "no available ip",
        "no available ips",
        "ipam exhausted",
        "address pool exhausted",
        "failed to allocate ip",
        "failed to assign an ip",
        "container runtime is down",
        "failed to connect to container runtime",
        "runtime.v1.runtimeservice",
        "containerd.sock",
        "cri-o.sock",
        "connection refused",
    )
    SUCCESS_REASONS = {
        "AddedInterface",
        "Created",
        "Started",
    }

    NAD_NAME_PATTERNS = (
        re.compile(
            r"network-attachment-definitions"
            r'(?:\.k8s\.cni\.cncf\.io)?\s+"([^"]+)"\s+not found',
            re.IGNORECASE,
        ),
        re.compile(
            r"network-attachment-definition\s+\(?([a-z0-9.-]+/[a-z0-9.-]+)\)?\s+not found",
            re.IGNORECASE,
        ),
        re.compile(
            r"cannot find a network-attachment-definition\s+\(?([a-z0-9.-]+/[a-z0-9.-]+)\)?",
            re.IGNORECASE,
        ),
        re.compile(
            r"failed (?:getting|to get) network\s+\"?([a-z0-9.-]+/[a-z0-9.-]+|[a-z0-9.-]+)\"?",
            re.IGNORECASE,
        ),
    )

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        raw = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _ordered_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        indexed = list(enumerate(events))
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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "").lower()

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject", {})
        if not isinstance(involved, dict):
            return True

        kind = str(involved.get("kind", "") or "").lower()
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace")

        if kind and kind != "pod":
            return False
        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False
        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False
        return True

    def _annotation_value(self, pod: dict[str, Any]) -> str:
        annotations = pod.get("metadata", {}).get("annotations", {}) or {}
        value = annotations.get(self.NETWORKS_ANNOTATION)
        return value if isinstance(value, str) else ""

    def _clean_network_ref(self, raw: str, default_namespace: str) -> str | None:
        ref = raw.strip().strip('"').strip("'")
        if not ref:
            return None

        ref = ref.split("@", 1)[0].strip()
        if not ref:
            return None

        if "/" in ref:
            namespace, name = ref.split("/", 1)
        else:
            namespace, name = default_namespace, ref

        namespace = namespace.strip()
        name = name.strip()
        if not namespace or not name:
            return None
        return f"{namespace}/{name}"

    def _resolve_with_annotation_namespace(
        self,
        ref: str,
        annotation_refs: list[str],
        default_namespace: str,
    ) -> str:
        namespace, name = ref.split("/", 1)
        if namespace != default_namespace:
            return ref

        matching_annotation_ref = next(
            (
                annotation_ref
                for annotation_ref in annotation_refs
                if annotation_ref.split("/", 1)[1] == name
            ),
            None,
        )
        return matching_annotation_ref or ref

    def _annotation_network_refs(self, pod: dict[str, Any]) -> list[str]:
        annotation = self._annotation_value(pod)
        if not annotation:
            return []

        namespace = pod.get("metadata", {}).get("namespace", "default")
        refs: list[str] = []

        try:
            parsed = json.loads(annotation)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            parsed = [parsed]

        if isinstance(parsed, list):
            for item in parsed:
                if isinstance(item, str):
                    ref = self._clean_network_ref(item, namespace)
                elif isinstance(item, dict):
                    name = item.get("name")
                    if not isinstance(name, str) or not name:
                        continue
                    item_namespace = item.get("namespace")
                    if not isinstance(item_namespace, str) or not item_namespace:
                        item_namespace = namespace
                    ref = self._clean_network_ref(f"{item_namespace}/{name}", namespace)
                else:
                    continue

                if ref and ref not in refs:
                    refs.append(ref)
            return refs

        for piece in annotation.split(","):
            ref = self._clean_network_ref(piece, namespace)
            if ref and ref not in refs:
                refs.append(ref)
        return refs

    def _extract_missing_refs(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> list[str]:
        message = self._message(event)
        namespace = pod.get("metadata", {}).get("namespace", "default")
        annotation_refs = self._annotation_network_refs(pod)
        refs: list[str] = []

        for pattern in self.NAD_NAME_PATTERNS:
            for match in pattern.findall(message):
                ref = self._clean_network_ref(match, namespace)
                if ref:
                    ref = self._resolve_with_annotation_namespace(
                        ref,
                        annotation_refs,
                        namespace,
                    )
                if ref and ref not in refs:
                    refs.append(ref)

        if refs:
            return refs

        for ref in annotation_refs:
            _, name = ref.split("/", 1)
            if name.lower() in message.lower() and ref not in refs:
                refs.append(ref)

        return refs

    def _has_nad_context(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        text = self._message(event).lower()
        if any(marker in text for marker in self.MULTUS_OR_NAD_MARKERS):
            return True
        return bool(self._annotation_network_refs(pod))

    def _has_missing_context(self, event: dict[str, Any]) -> bool:
        text = self._message(event).lower()
        if "not found" in text and any(
            marker in text for marker in self.MISSING_MARKERS
        ):
            return True
        return any(
            marker in text
            for marker in (
                "no network-attachment-definition",
                "cannot find a network-attachment-definition",
            )
        )

    def _is_excluded(self, event: dict[str, Any]) -> bool:
        text = self._message(event).lower()
        return any(marker in text for marker in self.EXCLUDED_MARKERS)

    def _is_missing_nad_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        if self._event_reason(event) not in self.SANDBOX_REASONS:
            return False
        if not self._targets_pod(event, pod):
            return False
        if self._is_excluded(event):
            return False
        if not self._has_nad_context(event, pod):
            return False
        if not self._has_missing_context(event):
            return False

        text = self._message(event).lower()
        return (
            "network-attachment-definition" in text
            or "network-attachment-definitions.k8s.cni.cncf.io" in text
            or bool(self._extract_missing_refs(event, pod))
        )

    def _recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        return self._ordered_events(timeline.events_within_window(self.WINDOW_MINUTES))

    def _matching_events(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return []
        return [
            event
            for event in self._recent_events(timeline)
            if self._is_missing_nad_event(event, pod)
        ]

    def _success_after_latest_failure(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        latest_failure_at: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if str(event.get("reason") or "") not in self.SUCCESS_REASONS:
                continue
            if not self._targets_pod(event, pod):
                continue

            event_at = self._event_time(event)
            if (
                latest_failure_at is None
                or event_at is None
                or event_at >= latest_failure_at
            ):
                return True
        return False

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        matches = self._matching_events(pod, context)
        if not matches:
            return False

        latest_failure_at = self._event_time(matches[-1])
        return not self._success_after_latest_failure(
            pod,
            timeline,
            latest_failure_at,
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError(
                "CNINetworkAttachmentDefinitionMissing requires Timeline context"
            )

        matches = self._matching_events(pod, context)
        if not matches:
            raise ValueError(
                "CNINetworkAttachmentDefinitionMissing explain() called without match"
            )

        latest = matches[-1]
        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")
        node_name = pod.get("spec", {}).get("nodeName", "<unassigned>")
        latest_message = self._message(latest).strip()
        latest_reason = str(latest.get("reason") or "FailedCreatePodSandBox")
        annotation_refs = self._annotation_network_refs(pod)
        missing_refs = self._extract_missing_refs(latest, pod)
        if not missing_refs and annotation_refs:
            missing_refs = annotation_refs

        total_occurrences = sum(self._occurrences(event) for event in matches)
        duration_seconds = timeline.duration_between(
            lambda event: self._is_missing_nad_event(event, pod)
        )

        missing_refs_text = ", ".join(missing_refs) if missing_refs else "<unknown>"

        chain = CausalChain(
            causes=[
                Cause(
                    code="MULTUS_SECONDARY_NETWORK_REQUESTED",
                    message="Pod requests one or more Multus secondary networks via k8s.v1.cni.cncf.io/networks",
                    role="configuration_context",
                ),
                Cause(
                    code="NETWORK_ATTACHMENT_DEFINITION_MISSING",
                    message="A referenced NetworkAttachmentDefinition could not be found",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_NETWORKING_BLOCKED",
                    message="Pod sandbox creation cannot complete because Multus cannot build the requested network delegates",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} is Pending while kubelet creates the sandbox",
            (
                "Pod declares Multus network attachment(s): "
                f"{', '.join(annotation_refs) if annotation_refs else '<not captured>'}"
            ),
            f"Missing NetworkAttachmentDefinition reference(s): {missing_refs_text}",
            f"Latest missing-NAD event reason: {latest_reason}",
            f"Latest missing-NAD message: {latest_message}",
            f"Observed {total_occurrences} missing NetworkAttachmentDefinition failure occurrence(s) within {self.WINDOW_MINUTES} minutes",
            "No successful pod start or Multus AddedInterface event observed after the latest missing-NAD failure",
        ]
        if node_name != "<unassigned>":
            evidence.append(f"Pod is assigned to node {node_name}")
        if duration_seconds:
            evidence.append(
                f"Missing NetworkAttachmentDefinition failures persisted for {duration_seconds/60:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod sandbox creation is blocked by a missing Multus NetworkAttachmentDefinition",
                latest_message,
            ],
            "networkattachmentdefinition:missing": [
                f"Missing reference(s): {missing_refs_text}"
            ],
        }
        if node_name != "<unassigned>":
            object_evidence[f"node:{node_name}"] = [
                "Kubelet on the assigned node could not complete Multus delegate lookup"
            ]

        return {
            "root_cause": "Multus NetworkAttachmentDefinition referenced by Pod is missing",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The referenced NetworkAttachmentDefinition was never created in the Pod namespace or the explicitly referenced namespace",
                "The Pod annotation references the wrong NetworkAttachmentDefinition name or namespace",
                "A Helm, GitOps, or namespace provisioning step created the workload before creating the NetworkAttachmentDefinition",
                "The NetworkAttachmentDefinition was deleted or recreated under a different name while workloads still reference it",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get network-attachment-definitions.k8s.cni.cncf.io -A",
                "Verify the k8s.v1.cni.cncf.io/networks annotation names and namespaces",
                "Create or restore the missing NetworkAttachmentDefinition before restarting the Pod",
                "Check Multus logs on the assigned node for delegate lookup failures",
            ],
        }
