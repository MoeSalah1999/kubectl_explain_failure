from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class APIServerUnreachableRule(FailureRule):
    """
    Detects a kube-apiserver outage that is directly impacting control-plane
    clients or controller-managed workloads.
    """

    name = "APIServerUnreachable"
    category = "Controller"
    priority = 66
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pod"],
        "optional_objects": [
            "service",
            "endpoints",
            "endpointslice",
            "deployment",
            "replicaset",
            "statefulset",
            "daemonset",
        ],
    }
    blocks = [
        "CrashLoopBackOff",
        "ControllerManagerLeaderElectionFailure",
        "ControllerManagerUnavailable",
        "DeploymentReplicaMismatch",
        "DeploymentProgressDeadlineExceeded",
        "LivenessProbeFailure",
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
    ]

    WINDOW_MINUTES = 20
    MAX_CORROBORATION_GAP = timedelta(minutes=5)
    CACHE_KEY = "_apiserver_unreachable_candidate"

    APISERVER_NAMES = ("kube-apiserver", " apiserver", "apiserver-")
    CONTROL_PLANE_CLIENT_NAMES = (
        "kube-controller-manager",
        "controller-manager",
        "kube-scheduler",
        "scheduler",
        "cloud-controller-manager",
    )
    DIRECT_OUTAGE_REASONS = {"backoff", "failed", "unhealthy"}
    # /healthz is deprecated, but older clusters and kubelet events still emit it.
    DIRECT_OUTAGE_MARKERS = (
        "kube-apiserver",
        "/readyz",
        "/livez",
        "/healthz",
        "6443",
        "connection refused",
        "i/o timeout",
        "context deadline exceeded",
        "tls handshake timeout",
        "eof",
        "failed probe",
        "probe failed",
    )
    API_FAILURE_MARKERS = (
        "dial tcp",
        "i/o timeout",
        "context deadline exceeded",
        "tls handshake timeout",
        "connection refused",
        "connect: connection refused",
        "no route to host",
        "network is unreachable",
        "eof",
        "net/http: request canceled",
        "the connection to the server",
        "server was unable to return a response",
    )
    API_EXCLUSION_MARKERS = (
        "forbidden",
        "unauthorized",
        "x509",
        "certificate signed by unknown authority",
        "bad certificate",
        "no such host",
        "nxdomain",
    )

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _ordered_recent(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_ts(item[1]) is None else 0,
                    self._event_ts(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _pod_text(self, pod_obj: dict[str, Any]) -> str:
        metadata = pod_obj.get("metadata", {})
        labels = metadata.get("labels", {}) or {}
        spec = pod_obj.get("spec", {}) or {}
        status = pod_obj.get("status", {}) or {}

        values = [
            metadata.get("name", ""),
            metadata.get("namespace", ""),
            labels.get("component", ""),
            labels.get("tier", ""),
            *labels.keys(),
            *labels.values(),
            *[
                c.get("name", "")
                for c in spec.get("containers", []) or []
                if isinstance(c, dict)
            ],
            *[
                c.get("name", "")
                for c in status.get("containerStatuses", []) or []
                if isinstance(c, dict)
            ],
        ]
        return " ".join(str(value).lower() for value in values if value)

    def _is_apiserver_pod(self, pod_obj: dict[str, Any]) -> bool:
        if pod_obj.get("metadata", {}).get("namespace") != "kube-system":
            return False
        text = self._pod_text(pod_obj)
        return any(marker in text for marker in self.APISERVER_NAMES)

    def _is_control_plane_client_pod(self, pod_obj: dict[str, Any]) -> bool:
        if pod_obj.get("metadata", {}).get("namespace") != "kube-system":
            return False
        if self._is_apiserver_pod(pod_obj):
            return False
        text = self._pod_text(pod_obj)
        return any(marker in text for marker in self.CONTROL_PLANE_CLIENT_NAMES)

    def _apiserver_pods(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        pod_objects = context.get("objects", {}).get("pod", {})
        return [
            pod_obj
            for pod_obj in pod_objects.values()
            if isinstance(pod_obj, dict) and self._is_apiserver_pod(pod_obj)
        ]

    def _container_state_name(self, status: dict[str, Any]) -> str:
        state = status.get("state", {}) or {}
        if "waiting" in state:
            return "waiting"
        if "terminated" in state:
            return "terminated"
        if "running" in state:
            return "running"
        return "unknown"

    def _apiserver_outage_status(
        self, apiserver_pod: dict[str, Any]
    ) -> dict[str, Any] | None:
        statuses = apiserver_pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if not isinstance(status, dict):
                continue
            name = str(status.get("name", "")).lower()
            if "apiserver" not in name:
                continue
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            terminated = state.get("terminated", {}) or {}
            if (
                not bool(status.get("ready", False))
                or waiting.get("reason") == "CrashLoopBackOff"
                or terminated
                or int(status.get("restartCount", 0) or 0) > 0
            ):
                return status
        return None

    def _event_targets_pod(
        self, event: dict[str, Any], pod_obj: dict[str, Any]
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        if not isinstance(involved, dict):
            return False
        name = pod_obj.get("metadata", {}).get("name")
        namespace = pod_obj.get("metadata", {}).get("namespace")
        if involved.get("name") and involved.get("name") != name:
            return False
        if involved.get("namespace") and involved.get("namespace") != namespace:
            return False
        kind = str(involved.get("kind", "")).lower()
        return kind in {"", "pod"}

    def _service_ready(
        self,
        objects: dict[str, Any],
        service_name: str,
        namespace: str,
    ) -> bool | None:
        service_obj = self._find_named_object(
            objects, "service", service_name, namespace
        )
        if service_obj is None:
            return None

        endpoints = self._find_named_object(
            objects, "endpoints", service_name, namespace
        )
        if endpoints:
            for subset in endpoints.get("subsets", []) or []:
                if subset.get("addresses"):
                    return True
            return False

        for slice_obj in objects.get("endpointslice", {}).values():
            if not isinstance(slice_obj, dict):
                continue
            metadata = slice_obj.get("metadata", {})
            if metadata.get("namespace", "default") != namespace:
                continue
            labels = metadata.get("labels", {})
            if labels.get("kubernetes.io/service-name") != service_name:
                continue
            if any(
                endpoint.get("conditions", {}).get("ready") is True
                for endpoint in slice_obj.get("endpoints", []) or []
            ):
                return True
            return False

        return None

    def _api_target_markers(self, objects: dict[str, Any]) -> set[str]:
        markers = {
            "https://127.0.0.1:6443",
            "127.0.0.1:6443",
            "https://localhost:6443",
            "localhost:6443",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "https://kubernetes.default.svc:443",
            "https://kubernetes.default.svc.cluster.local:443",
        }

        kubernetes_service = self._find_named_object(
            objects, "service", "kubernetes", "default"
        )
        if kubernetes_service:
            cluster_ip = kubernetes_service.get("spec", {}).get("clusterIP")
            if cluster_ip and cluster_ip != "None":
                cluster_ip = str(cluster_ip).lower()
                markers.update(
                    {
                        cluster_ip,
                        f"{cluster_ip}:443",
                        f"https://{cluster_ip}:443",
                    }
                )

        return markers

    def _direct_outage_events(
        self,
        apiserver_pod: dict[str, Any],
        ordered_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for event in ordered_events:
            if not self._event_targets_pod(event, apiserver_pod):
                continue
            if self._reason(event) not in self.DIRECT_OUTAGE_REASONS:
                continue
            message = self._message(event)
            if any(marker in message for marker in self.DIRECT_OUTAGE_MARKERS):
                results.append(event)
        return results

    def _direct_event_rank(self, event: dict[str, Any]) -> tuple[int, int]:
        message = self._message(event)
        return (
            int("/readyz" in message or "/livez" in message or "/healthz" in message),
            int("connection refused" in message or "i/o timeout" in message),
        )

    def _is_api_failure_event(
        self, event: dict[str, Any], objects: dict[str, Any]
    ) -> bool:
        message = self._message(event)
        if not message:
            return False
        if any(marker in message for marker in self.API_EXCLUSION_MARKERS):
            return False
        if not any(marker in message for marker in self.API_FAILURE_MARKERS):
            return False
        return any(marker in message for marker in self._api_target_markers(objects))

    def _corroborating_client_event(
        self,
        ordered_events: list[dict[str, Any]],
        *,
        objects: dict[str, Any],
        after: datetime | None,
        apiserver_pod: dict[str, Any],
    ) -> dict[str, Any] | None:
        for event in ordered_events:
            event_ts = self._event_ts(event)
            if after is not None:
                if event_ts is None or event_ts < after:
                    continue
                if event_ts - after > self.MAX_CORROBORATION_GAP:
                    continue
            if self._event_targets_pod(event, apiserver_pod):
                continue
            if self._is_api_failure_event(event, objects):
                return event
        return None

    def _owner_ref(self, obj: dict[str, Any], kind: str) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
                return str(ref["name"])
        return None

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict):
            if direct.get("metadata", {}).get("namespace", "default") == namespace:
                return direct
        for obj in objects.get(kind, {}).values():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", "default") != namespace:
                continue
            return obj
        return None

    def _workload_symptom(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, str] | None:
        objects = context.get("objects", {})
        namespace = pod.get("metadata", {}).get("namespace", "default")

        deployment_name = self._owner_ref(pod, "Deployment")
        rs_name = self._owner_ref(pod, "ReplicaSet")
        if deployment_name is None and rs_name is not None:
            rs_obj = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs_obj is not None:
                deployment_name = self._owner_ref(rs_obj, "Deployment")

        if deployment_name:
            deployment = self._find_named_object(
                objects, "deployment", deployment_name, namespace
            )
            if deployment:
                status = deployment.get("status", {}) or {}
                desired = int(
                    status.get(
                        "replicas", deployment.get("spec", {}).get("replicas", 0)
                    )
                    or 0
                )
                available = int(status.get("availableReplicas", 0) or 0)
                updated = int(status.get("updatedReplicas", 0) or 0)
                if desired > 0 and available < desired:
                    return {
                        "kind": "deployment",
                        "name": deployment_name,
                        "message": f"Deployment '{deployment_name}' remains at {available}/{desired} available replicas while only {updated}/{desired} replicas are updated",
                    }

        if rs_name:
            rs_obj = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs_obj:
                status = rs_obj.get("status", {}) or {}
                available = int(status.get("availableReplicas", 0) or 0)
                if available == 0:
                    return {
                        "kind": "replicaset",
                        "name": rs_name,
                        "message": f"ReplicaSet '{rs_name}' has zero available replicas",
                    }

        statefulset_name = self._owner_ref(pod, "StatefulSet")
        if statefulset_name:
            sts = self._find_named_object(
                objects, "statefulset", statefulset_name, namespace
            )
            if sts:
                status = sts.get("status", {}) or {}
                desired = int(sts.get("spec", {}).get("replicas", 0) or 0)
                ready = int(status.get("readyReplicas", 0) or 0)
                if desired > 0 and ready < desired:
                    return {
                        "kind": "statefulset",
                        "name": statefulset_name,
                        "message": f"StatefulSet '{statefulset_name}' remains at {ready}/{desired} ready replicas",
                    }

        daemonset_name = self._owner_ref(pod, "DaemonSet")
        if daemonset_name:
            ds = self._find_named_object(
                objects, "daemonset", daemonset_name, namespace
            )
            if ds:
                status = ds.get("status", {}) or {}
                desired = int(status.get("desiredNumberScheduled", 0) or 0)
                available = int(status.get("numberAvailable", 0) or 0)
                if desired > 0 and available < desired:
                    return {
                        "kind": "daemonset",
                        "name": daemonset_name,
                        "message": f"DaemonSet '{daemonset_name}' remains at {available}/{desired} available nodes",
                    }

        return None

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        ordered_events = self._ordered_recent(timeline)
        if not ordered_events:
            return None

        objects = context.get("objects", {})
        api_service_ready = self._service_ready(objects, "kubernetes", "default")
        workload_symptom = self._workload_symptom(pod, context)
        pod_is_apiserver = self._is_apiserver_pod(pod)
        pod_is_control_plane_client = self._is_control_plane_client_pod(pod)

        best: dict[str, Any] | None = None

        for apiserver_pod in self._apiserver_pods(context):
            outage_status = self._apiserver_outage_status(apiserver_pod)
            direct_events = self._direct_outage_events(apiserver_pod, ordered_events)
            direct_event = (
                max(direct_events, key=self._direct_event_rank)
                if direct_events
                else None
            )
            direct_ts = self._event_ts(direct_event) if direct_event else None
            downstream_event = self._corroborating_client_event(
                ordered_events,
                objects=objects,
                after=direct_ts,
                apiserver_pod=apiserver_pod,
            )

            has_primary_signal = (
                outage_status is not None
                and (direct_event is not None or api_service_ready is False)
            ) or (api_service_ready is False and direct_event is not None)
            if not has_primary_signal:
                continue

            affected_scope = (
                pod_is_apiserver
                or pod_is_control_plane_client
                or downstream_event is not None
                or workload_symptom is not None
            )
            if not affected_scope:
                continue

            candidate = {
                "apiserver_pod_name": apiserver_pod.get("metadata", {}).get(
                    "name", "<unknown>"
                ),
                "apiserver_container_name": (outage_status or {}).get(
                    "name", "kube-apiserver"
                ),
                "apiserver_state_name": self._container_state_name(outage_status or {}),
                "apiserver_restart_count": int(
                    (outage_status or {}).get("restartCount", 0) or 0
                ),
                "direct_outage_message": (
                    str(direct_event.get("message", "")).strip() if direct_event else ""
                ),
                "downstream_message": (
                    str(downstream_event.get("message", "")).strip()
                    if downstream_event
                    else ""
                ),
                "downstream_object_name": (
                    str(
                        (downstream_event.get("involvedObject", {}) or {}).get(
                            "name", ""
                        )
                    )
                    if downstream_event
                    else ""
                ),
                "api_service_ready": api_service_ready,
                "workload_symptom": workload_symptom,
                "pod_is_apiserver": pod_is_apiserver,
            }

            ranking = (
                int(api_service_ready is False),
                int(direct_event is not None),
                int(downstream_event is not None),
                int(workload_symptom is not None),
                candidate["apiserver_restart_count"],
            )
            if best is None or ranking > best["ranking"]:
                candidate["ranking"] = ranking
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError("APIServerUnreachable explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        apiserver_pod_name = candidate["apiserver_pod_name"]
        apiserver_container_name = candidate["apiserver_container_name"]
        workload_symptom = candidate["workload_symptom"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTROL_PLANE_REQUIRES_APISERVER",
                    message="Cluster control-plane components and API-dependent workloads require kube-apiserver reachability",
                    role="control_plane_context",
                ),
                Cause(
                    code="APISERVER_UNREACHABLE",
                    message="kube-apiserver is not reachable on its control-plane endpoint or through the kubernetes Service VIP",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="DOWNSTREAM_CONTROL_PLANE_STALL",
                    message="Control-plane clients and controller-managed workloads stop progressing when the API server cannot be reached",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Recent kube-apiserver outage targets pod '{apiserver_pod_name}' with container '{apiserver_container_name}' state={candidate['apiserver_state_name']} restartCount={candidate['apiserver_restart_count']}",
        ]
        if candidate["direct_outage_message"]:
            evidence.append(
                f"Representative kube-apiserver outage signal: {candidate['direct_outage_message']}"
            )
        if candidate["api_service_ready"] is False:
            evidence.append(
                "Kubernetes service 'kubernetes' currently has no ready API endpoints"
            )
        if candidate["downstream_message"]:
            evidence.append(
                f"Representative downstream API client failure: {candidate['downstream_message']}"
            )
        if workload_symptom is not None:
            evidence.append(
                f"Workload reconciliation symptom: {workload_symptom['message']}"
            )

        object_evidence = {
            f"pod:{apiserver_pod_name}": [
                candidate["direct_outage_message"]
                or "kube-apiserver container is unhealthy or repeatedly restarting"
            ],
            f"pod:{pod_name}": [
                "The pod depends on Kubernetes API reachability and is affected while kube-apiserver is unavailable"
            ],
        }
        if candidate["api_service_ready"] is False:
            object_evidence["service:kubernetes"] = [
                "No ready endpoints back the kubernetes Service VIP"
            ]
        if candidate["downstream_message"] and candidate["downstream_object_name"]:
            object_evidence[f"pod:{candidate['downstream_object_name']}"] = [
                candidate["downstream_message"]
            ]
        if workload_symptom is not None:
            object_evidence[
                f"{workload_symptom['kind']}:{workload_symptom['name']}"
            ] = [workload_symptom["message"]]

        confidence = 0.95
        if candidate["direct_outage_message"] and candidate["downstream_message"]:
            confidence = 0.97
        if candidate["api_service_ready"] is False:
            confidence = min(0.99, confidence + 0.01)

        return {
            "root_cause": "kube-apiserver is unreachable, so control-plane clients cannot talk to the Kubernetes API",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The kube-apiserver static pod is crashlooping or failing /readyz on the control-plane node",
                "Port 6443 or host-network reachability on the control-plane node is unavailable",
                "An etcd or local dependency failure is preventing kube-apiserver from becoming ready",
                "Static-pod manifest drift, certificate issues, or startup flag errors left kube-apiserver unhealthy",
            ],
            "suggested_checks": [
                f"kubectl describe pod {apiserver_pod_name} -n kube-system",
                f"kubectl logs -n kube-system {apiserver_pod_name} -c {apiserver_container_name}",
                "kubectl get endpoints kubernetes -n default -o yaml",
                "Inspect kube-apiserver /readyz and local 6443 listener health on the control-plane node",
                f"kubectl describe pod {pod_name}",
            ],
        }
