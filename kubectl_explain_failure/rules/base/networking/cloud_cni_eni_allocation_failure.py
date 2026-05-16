from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CloudCNIENIAllocationFailureRule(FailureRule):
    """
    Detects AWS VPC CNI-style pod sandbox failures where pod networking cannot
    be set up because ENI/private-IP allocation through the cloud CNI fails.

    This is narrower than generic CNI/IPAM exhaustion. It requires kubelet
    sandbox failure events with AWS VPC CNI / ipamd / EC2 ENI allocation
    language such as AssignPrivateIpAddresses, AttachNetworkInterface,
    CreateNetworkInterface, ENI limits, or subnet free-address exhaustion.
    """

    name = "CloudCNIENIAllocationFailure"
    category = "Networking"
    severity = "High"
    priority = 74
    deterministic = True
    phases = ["Pending"]
    blocks = [
        "CNIIPAMExhausted",
        "CNIIPExhaustion",
        "CNIPluginFailure",
    ]
    requires = {
        "context": ["timeline"],
        "optional_objects": ["node", "pod"],
    }

    window_minutes = 30

    SANDBOX_REASONS = {
        "FailedCreatePodSandBox",
        "FailedCreatePodSandbox",
    }
    AWS_CNI_MARKERS = (
        "aws-cni",
        "aws cni",
        "awscni",
        "amazon-vpc-cni",
        "amazon vpc cni",
        "amazonvpccni",
        "vpc cni",
        "vpccni",
        "aws vpc cni",
        "ipamd",
        "aws-node",
        "ec2",
    )
    ENI_ALLOCATION_MARKERS = (
        "eni",
        "elastic network interface",
        "assignprivateipaddresses",
        "assign private ip addresses",
        "attachnetworkinterface",
        "attach network interface",
        "createnetworkinterface",
        "create network interface",
        "failed to allocate eni",
        "failed to attach eni",
        "failed to create eni",
        "failed to assign pod eni",
        "failed to increase ip pool",
        "private ip address",
        "privateipaddress",
        "branch eni",
        "trunk eni",
        "warm eni target",
        "warm ip target",
    )
    CLOUD_FAILURE_MARKERS = (
        "insufficientfreeaddressesinsubnet",
        "insufficient free addresses in subnet",
        "insufficient cidr blocks",
        "insufficientcidrblocks",
        "privateipaddresslimitexceeded",
        "private ip address limit exceeded",
        "maximum number of network interfaces",
        "network interface limit",
        "eni limit",
        "too many interfaces",
        "subnet has no available ip",
        "no available ip addresses in subnet",
        "available ip address count is 0",
        "ec2 api",
        "ec2:",
        "aws api",
        "requestlimitexceeded",
        "throttling",
        "unauthorizedoperation",
        "accessdenied",
    )
    EXCLUDED_MARKERS = (
        "cni config uninitialized",
        "no networks found",
        "failed to load cni config",
        "failed to load netconf",
        "no such file or directory",
        "network plugin is not ready",
        "containerd.sock",
        "cri-o.sock",
        "runtime.v1",
        "connection refused",
        "runtimeclass",
    )
    SUCCESS_REASONS = {
        "Created",
        "Started",
        "Pulled",
        "SandboxChanged",
    }

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _normalized(self, text: str) -> str:
        return " ".join(
            text.lower()
            .replace("-", " ")
            .replace("_", " ")
            .replace(":", " ")
            .replace("/", " ")
            .split()
        )

    def _has_any(self, text: str, markers: tuple[str, ...]) -> bool:
        normalized = self._normalized(text)
        compact = normalized.replace(" ", "")
        return any(marker in normalized or marker in compact for marker in markers)

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        ts = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )
        if not isinstance(ts, str):
            return None
        try:
            return parse_time(ts)
        except Exception:
            return None

    def _occurrences(self, event: dict[str, Any]) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _is_eni_allocation_event(self, event: dict[str, Any]) -> bool:
        reason = str(event.get("reason") or "")
        if reason not in self.SANDBOX_REASONS:
            return False

        message = self._message(event)
        if self._has_any(message, self.EXCLUDED_MARKERS):
            return False

        source = self._source_component(event)
        if source and source != "kubelet":
            return False

        has_aws_cni = self._has_any(message, self.AWS_CNI_MARKERS)
        has_eni_allocation = self._has_any(message, self.ENI_ALLOCATION_MARKERS)
        has_cloud_failure = self._has_any(message, self.CLOUD_FAILURE_MARKERS)

        return has_aws_cni and has_eni_allocation and has_cloud_failure

    def _recent_eni_failures(self, timeline: Timeline) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_eni_allocation_event(event)
        ]

    def _success_after(self, timeline: Timeline, after: datetime | None) -> bool:
        for event in timeline.events:
            if str(event.get("reason") or "") not in self.SUCCESS_REASONS:
                continue
            event_at = self._event_time(event)
            if after is None or event_at is None or event_at >= after:
                return True
        return False

    def _affected_pod_names(self, events: list[dict[str, Any]]) -> list[str]:
        names = []
        for event in events:
            involved = event.get("involvedObject", {})
            name = involved.get("name")
            if isinstance(name, str) and name and name not in names:
                names.append(name)
        return names

    def matches(self, pod, events, context) -> bool:
        if get_pod_phase(pod) != "Pending":
            return False

        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False

        failures = self._recent_eni_failures(timeline)
        if not failures:
            return False

        latest_failure_at = self._event_time(failures[-1])
        if self._success_after(timeline, latest_failure_at):
            return False

        pod_name = pod.get("metadata", {}).get("name")
        affected_pods = self._affected_pod_names(failures)
        total_occurrences = sum(self._occurrences(event) for event in failures)

        current_pod_seen = not affected_pods or pod_name in affected_pods
        return current_pod_seen or total_occurrences >= 2 or len(affected_pods) >= 2

    def explain(self, pod, events, context):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("CloudCNIENIAllocationFailure requires Timeline context")

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")
        node_name = pod.get("spec", {}).get("nodeName", "<unassigned>")

        failures = self._recent_eni_failures(timeline)
        representative = next(
            (
                event
                for event in reversed(failures)
                if event.get("involvedObject", {}).get("name") == pod_name
            ),
            failures[-1] if failures else {},
        )
        representative_message = self._message(representative)
        representative_reason = str(representative.get("reason") or "<unknown>")
        total_occurrences = sum(self._occurrences(event) for event in failures)
        affected_pods = self._affected_pod_names(failures)
        duration_seconds = timeline.duration_between(self._is_eni_allocation_event)

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_SANDBOX_NETWORK_SETUP",
                    message="Kubelet attempted to create the Pod sandbox and attach AWS VPC CNI networking",
                    role="runtime_context",
                ),
                Cause(
                    code="AWS_VPC_CNI_ENI_ALLOCATION_FAILED",
                    message="AWS VPC CNI could not allocate or attach ENI/private-IP capacity for the Pod",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_CREATION_BLOCKED",
                    message="Pod sandbox creation failed because cloud CNI networking could not allocate pod network capacity",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod sandbox creation is blocked by AWS VPC CNI ENI/private-IP allocation failure",
                representative_message,
            ]
        }
        if node_name != "<unassigned>":
            object_evidence[f"node:{node_name}"] = [
                "Assigned node could not obtain AWS VPC CNI ENI/private-IP capacity"
            ]
        if affected_pods:
            object_evidence["timeline:eni_failures"] = [
                f"Affected pod(s): {', '.join(affected_pods)}"
            ]

        evidence = [
            f"Pod {namespace}/{pod_name} remains Pending during sandbox creation",
            f"Latest ENI allocation failure event reason: {representative_reason}",
            f"Latest ENI allocation failure message: {representative_message}",
            f"Observed {total_occurrences} AWS VPC CNI ENI/IP allocation failure occurrence(s) within {self.window_minutes} minutes",
            "No successful container start observed after the latest ENI allocation failure",
        ]
        if node_name != "<unassigned>":
            evidence.append(f"Pod is assigned to node {node_name}")
        if affected_pods:
            evidence.append(f"Timeline affected pod(s): {', '.join(affected_pods)}")
        if duration_seconds:
            evidence.append(
                f"AWS VPC CNI ENI/IP allocation failures persisted for {duration_seconds/60:.1f} minutes"
            )

        return {
            "root_cause": "AWS VPC CNI failed to allocate ENI or private IP capacity for pod networking",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Subnet free IP addresses are exhausted for the node group",
                "The instance reached its ENI or secondary private IP limit",
                "AWS VPC CNI ipamd cannot attach an ENI or assign private IPs through the EC2 API",
                "EC2 API throttling or IAM permissions are preventing ENI/private-IP allocation",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl -n kube-system logs daemonset/aws-node -c aws-node",
                "Inspect aws-node/ipamd logs for AssignPrivateIpAddresses, AttachNetworkInterface, or CreateNetworkInterface errors",
                "Check subnet free IP count, instance ENI/IP limits, WARM_IP_TARGET, and WARM_ENI_TARGET",
                "Verify the aws-node IAM role can call required EC2 network-interface and private-IP APIs",
            ],
        }
