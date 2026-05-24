from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ConfigMapRolloutDriftRule(FailureRule):
    """
    Detects controller/config drift where a ConfigMap changed but running Pods
    are still on an older configuration revision.

    Real-world behavior:
    - ConfigMap values consumed through env/envFrom are fixed when the container
      starts; changing the ConfigMap does not update already-running containers
    - ConfigMap volume mounts using subPath also stay pinned until the Pod is
      recreated
    - Deployments/StatefulSets/DaemonSets only roll Pods when the pod template
      changes, usually via checksum annotations, reloader automation, or a
      manual rollout restart
    - if a ConfigMap update is observed but no controller rollout follows, app
      symptoms after the change are often stale-config drift, not proof that the
      new config broke the container
    """

    name = "ConfigMapRolloutDrift"
    category = "Compound"
    severity = "Medium"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running", "CrashLoopBackOff"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["configmap"],
        "optional_objects": [
            "deployment",
            "replicaset",
            "statefulset",
            "daemonset",
        ],
    }

    blocks = [
        "ConfigChangedButPodNotRestarted",
        "CrashLoopAfterConfigChange",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "ReadinessProbeFailure",
        "LivenessProbeFailure",
        "StartupProbeFailure",
    ]

    WINDOW_MINUTES = 45
    MIN_ROLLOUT_OBSERVATION_SECONDS = 60
    CACHE_KEY = "_config_map_rollout_drift_candidate"

    CONFIG_UPDATE_REASONS = {
        "ConfigMapUpdated",
        "ConfigMapChange",
        "Updated",
        "Modified",
        "Applied",
    }

    ROLLOUT_REASONS = {
        "Killing",
        "Started",
        "SuccessfulCreate",
        "SuccessfulDelete",
        "ScalingReplicaSet",
        "DeploymentUpdated",
        "ReplicaSetUpdated",
        "Pulled",
        "Created",
    }

    SYMPTOM_REASONS = {
        "BackOff",
        "CrashLoopBackOff",
        "Unhealthy",
        "Failed",
        "Warning",
    }

    RESTART_ANNOTATION_KEYS = (
        "kubectl.kubernetes.io/restartedAt",
        "reloader.stakater.com/last-reloaded-from",
        "configmap.reloader.stakater.com/reload-time",
        "rollout.kubernetes.io/restartedAt",
    )

    CHECKSUM_ANNOTATION_MARKERS = (
        "checksum/config",
        "checksum-config",
        "configmap-hash",
        "config-hash",
        "reloader.stakater.com",
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
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _event_end(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
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

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "")
        return str(source or "")

    def _pod_namespace(self, pod: dict[str, Any]) -> str:
        return str(pod.get("metadata", {}).get("namespace") or "default")

    def _pod_name(self, pod: dict[str, Any]) -> str:
        return str(pod.get("metadata", {}).get("name") or "<pod>")

    def _pod_start_time(self, pod: dict[str, Any]) -> datetime | None:
        status = pod.get("status", {}) or {}
        pod_start = self._parse_timestamp(status.get("startTime"))
        if pod_start:
            return pod_start

        starts: list[datetime] = []
        for container_status in status.get("containerStatuses", []) or []:
            state = container_status.get("state", {}) or {}
            running = state.get("running", {}) or {}
            started_at = self._parse_timestamp(running.get("startedAt"))
            if started_at:
                starts.append(started_at)
        return min(starts) if starts else None

    def _latest_container_start(self, pod: dict[str, Any]) -> datetime | None:
        starts: list[datetime] = []
        for container_status in (
            pod.get("status", {}).get("containerStatuses", []) or []
        ):
            state = container_status.get("state", {}) or {}
            last_state = container_status.get("lastState", {}) or {}
            for section in (
                state.get("running", {}) or {},
                last_state.get("terminated", {}) or {},
            ):
                for key in ("startedAt", "finishedAt"):
                    ts = self._parse_timestamp(section.get(key))
                    if ts:
                        starts.append(ts)
        return max(starts) if starts else self._pod_start_time(pod)

    def _configmap_volume_names(self, pod: dict[str, Any]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for volume in (pod.get("spec", {}) or {}).get("volumes", []) or []:
            config_map = volume.get("configMap") or {}
            name = config_map.get("name")
            if name and volume.get("name"):
                mapping[str(volume["name"])] = str(name)
            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_cm = source.get("configMap") or {}
                if projected_cm.get("name") and volume.get("name"):
                    mapping[str(volume["name"])] = str(projected_cm["name"])
        return mapping

    def _collect_configmap_refs(self, pod: dict[str, Any]) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}
        spec = pod.get("spec", {}) or {}
        cm_volumes = self._configmap_volume_names(pod)

        def add(name: str | None, surface: str, restart_required: bool) -> None:
            if not name:
                return
            refs.setdefault(str(name), [])
            suffix = "restart-required" if restart_required else "volume-refresh"
            item = f"{surface} ({suffix})"
            if item not in refs[str(name)]:
                refs[str(name)].append(item)

        for container_group in ("initContainers", "containers", "ephemeralContainers"):
            for container in spec.get(container_group, []) or []:
                container_name = str(container.get("name") or "<container>")
                for env in container.get("env", []) or []:
                    cm_ref = (env.get("valueFrom") or {}).get("configMapKeyRef") or {}
                    add(
                        cm_ref.get("name"),
                        f"Referenced by env '{env.get('name', '<env>')}' in container '{container_name}'",
                        True,
                    )
                for env_from in container.get("envFrom", []) or []:
                    cm_ref = env_from.get("configMapRef") or {}
                    add(
                        cm_ref.get("name"),
                        f"Referenced by envFrom in container '{container_name}'",
                        True,
                    )
                for mount in container.get("volumeMounts", []) or []:
                    volume_name = str(mount.get("name") or "")
                    cm_name = cm_volumes.get(volume_name)
                    if not cm_name:
                        continue
                    add(
                        cm_name,
                        f"Mounted through ConfigMap volume '{volume_name}' in container '{container_name}'",
                        bool(mount.get("subPath") or mount.get("subPathExpr")),
                    )

        for volume_name, cm_name in cm_volumes.items():
            add(cm_name, f"Referenced by ConfigMap volume '{volume_name}'", False)

        return refs

    def _restart_required_surfaces(self, refs: list[str]) -> list[str]:
        return [item for item in refs if "restart-required" in item]

    def _configmap_update_times(
        self,
        cm_name: str,
        cm: dict[str, Any],
        events: list[dict[str, Any]],
        namespace: str,
    ) -> list[tuple[datetime, str]]:
        updates: list[tuple[datetime, str]] = []
        metadata = cm.get("metadata", {}) or {}

        created = self._parse_timestamp(metadata.get("creationTimestamp"))
        if created:
            updates.append((created, "ConfigMap creation timestamp"))

        for field in metadata.get("managedFields", []) or []:
            if not isinstance(field, dict):
                continue
            ts = self._parse_timestamp(field.get("time"))
            manager = field.get("manager")
            if ts:
                updates.append((ts, f"managedFields update by {manager or 'unknown'}"))

        for event in events:
            involved = event.get("involvedObject")
            if isinstance(involved, dict):
                kind = str(involved.get("kind") or "").lower()
                name = str(involved.get("name") or "")
                event_namespace = str(involved.get("namespace") or namespace)
                if kind and kind != "configmap":
                    continue
                if name and name != cm_name:
                    continue
                if event_namespace != namespace:
                    continue
            text = f"{self._reason(event)} {self._message(event)}".lower()
            if cm_name.lower() not in text and not isinstance(involved, dict):
                continue
            if self._reason(event) not in self.CONFIG_UPDATE_REASONS and not any(
                marker in text
                for marker in (
                    "configmap",
                    "config map",
                    "updated",
                    "modified",
                    "applied",
                )
            ):
                continue
            ts = self._event_end(event) or self._event_time(event)
            if ts:
                updates.append((ts, f"timeline event {self._reason(event)}"))

        return sorted(updates, key=lambda item: item[0])

    def _selector_matches(
        self, selector: dict[str, Any] | None, labels: dict[str, Any]
    ) -> bool:
        if selector is None:
            return False
        if not selector:
            return True
        if "matchLabels" in selector or "matchExpressions" in selector:
            match_labels = selector.get("matchLabels", {}) or {}
        else:
            match_labels = selector
        for key, expected in match_labels.items():
            if labels.get(key) != expected:
                return False
        for expr in selector.get("matchExpressions", []) or []:
            key = expr.get("key")
            operator = expr.get("operator")
            values = expr.get("values", []) or []
            actual = labels.get(key)
            if operator == "In" and actual not in values:
                return False
            if operator == "NotIn" and actual in values:
                return False
            if operator == "Exists" and actual is None:
                return False
            if operator == "DoesNotExist" and actual is not None:
                return False
        return True

    def _owner_names(self, pod: dict[str, Any], context: dict[str, Any]) -> set[str]:
        names = {self._pod_name(pod)}
        for owner in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if isinstance(owner, dict) and owner.get("name"):
                names.add(str(owner["name"]))
                if owner.get("kind") == "ReplicaSet":
                    rs_obj = (
                        context.get("objects", {}).get("replicaset", {}) or {}
                    ).get(owner["name"])
                    if isinstance(rs_obj, dict):
                        for rs_owner in (
                            rs_obj.get("metadata", {}).get("ownerReferences", []) or []
                        ):
                            if isinstance(rs_owner, dict) and rs_owner.get("name"):
                                names.add(str(rs_owner["name"]))
        return names

    def _matching_controllers(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        labels = pod.get("metadata", {}).get("labels", {}) or {}
        namespace = self._pod_namespace(pod)
        owner_names = self._owner_names(pod, context)
        controllers: list[dict[str, Any]] = []

        for kind in ("deployment", "statefulset", "daemonset"):
            for name, obj in (objects.get(kind, {}) or {}).items():
                if not isinstance(obj, dict):
                    continue
                metadata = obj.get("metadata", {}) or {}
                if metadata.get("namespace", "default") != namespace:
                    continue
                object_name = str(metadata.get("name") or name)
                selector = (obj.get("spec", {}) or {}).get("selector")
                if object_name in owner_names or self._selector_matches(
                    selector, labels
                ):
                    controllers.append(
                        {"kind": kind, "name": object_name, "object": obj}
                    )
        return controllers

    def _template_rollout_times(
        self, controller: dict[str, Any]
    ) -> list[tuple[datetime, str]]:
        obj = controller["object"]
        annotations = ((obj.get("spec", {}) or {}).get("template", {}) or {}).get(
            "metadata", {}
        ).get("annotations", {}) or {}
        times: list[tuple[datetime, str]] = []
        for key in self.RESTART_ANNOTATION_KEYS:
            ts = self._parse_timestamp(annotations.get(key))
            if ts:
                times.append((ts, f"pod template annotation {key}"))
        return times

    def _has_config_checksum_annotation(self, controller: dict[str, Any]) -> bool:
        obj = controller["object"]
        annotations = ((obj.get("spec", {}) or {}).get("template", {}) or {}).get(
            "metadata", {}
        ).get("annotations", {}) or {}
        text = " ".join(annotations.keys()).lower()
        return any(marker in text for marker in self.CHECKSUM_ANNOTATION_MARKERS)

    def _rollout_events_after(
        self,
        events: list[dict[str, Any]],
        after: datetime,
        names: set[str],
        namespace: str,
    ) -> list[dict[str, Any]]:
        rollout_events = []
        for event in events:
            ts = self._event_time(event)
            if ts is None or ts <= after + timedelta(
                seconds=self.MIN_ROLLOUT_OBSERVATION_SECONDS
            ):
                continue
            reason = self._reason(event)
            message = self._message(event)
            text = f"{reason} {message} {self._source_component(event)}".lower()
            involved = event.get("involvedObject")
            if isinstance(involved, dict):
                event_namespace = str(involved.get("namespace") or namespace)
                if event_namespace != namespace:
                    continue
                involved_name = str(involved.get("name") or "")
                if involved_name and involved_name not in names:
                    if not any(name.lower() in text for name in names):
                        continue
            elif not any(name.lower() in text for name in names):
                continue
            if reason in self.ROLLOUT_REASONS or any(
                marker in text
                for marker in (
                    "rollout",
                    "scalingreplicaset",
                    "created pod",
                    "killing container",
                )
            ):
                rollout_events.append(event)
        return rollout_events

    def _symptoms_after(
        self,
        events: list[dict[str, Any]],
        after: datetime,
        pod: dict[str, Any],
    ) -> list[dict[str, Any]]:
        symptoms = []
        pod_name = self._pod_name(pod)
        namespace = self._pod_namespace(pod)
        for event in events:
            ts = self._event_time(event)
            if ts is None or ts < after:
                continue
            involved = event.get("involvedObject")
            if isinstance(involved, dict):
                if str(involved.get("namespace") or namespace) != namespace:
                    continue
                if str(involved.get("name") or "") not in {"", pod_name}:
                    continue
            reason = self._reason(event)
            text = f"{reason} {self._message(event)}".lower()
            if reason in self.SYMPTOM_REASONS or any(
                marker in text
                for marker in (
                    "crashloopbackoff",
                    "readiness probe failed",
                    "stale config",
                    "old config",
                )
            ):
                symptoms.append(event)
        return symptoms

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        namespace = self._pod_namespace(pod)
        pod_start = self._pod_start_time(pod)
        latest_container_start = self._latest_container_start(pod)
        if pod_start is None or latest_container_start is None:
            return None

        refs = self._collect_configmap_refs(pod)
        if not refs:
            return None

        objects = context.get("objects", {}) or {}
        configmaps = objects.get("configmap", {}) or {}
        if not configmaps:
            return None

        ordered_events = self._ordered_recent_events(timeline)
        controllers = self._matching_controllers(pod, context)
        owner_names = self._owner_names(pod, context)
        owner_names.update(controller["name"] for controller in controllers)

        best: dict[str, Any] | None = None
        for cm_name, surfaces in refs.items():
            restart_required_surfaces = self._restart_required_surfaces(surfaces)
            if not restart_required_surfaces:
                continue

            cm_obj = configmaps.get(cm_name)
            if not isinstance(cm_obj, dict):
                continue

            updates = self._configmap_update_times(
                cm_name, cm_obj, ordered_events, namespace
            )
            updates_after_start = [
                item
                for item in updates
                if item[0] > pod_start and item[0] > latest_container_start
            ]
            if not updates_after_start:
                continue

            config_time, update_source = updates_after_start[-1]

            template_rollouts = [
                (controller, rollout_time, source)
                for controller in controllers
                for rollout_time, source in self._template_rollout_times(controller)
                if rollout_time >= config_time
            ]
            rollout_events = self._rollout_events_after(
                ordered_events,
                config_time,
                owner_names,
                namespace,
            )
            if template_rollouts or rollout_events:
                continue

            symptoms = self._symptoms_after(ordered_events, config_time, pod)
            checksum_present = any(
                self._has_config_checksum_annotation(controller)
                for controller in controllers
            )

            def matches_config_event(
                event: dict[str, Any],
                name: str = cm_name,
            ) -> bool:
                text = f"{self._reason(event)} {self._message(event)}".lower()
                return (
                    name.lower() in text
                    or self._reason(event) in self.CONFIG_UPDATE_REASONS
                )

            candidate = {
                "configmap_name": cm_name,
                "config_time": config_time,
                "update_source": update_source,
                "surfaces": restart_required_surfaces,
                "controllers": controllers,
                "checksum_present": checksum_present,
                "symptoms": symptoms,
                "pod_start": pod_start,
                "latest_container_start": latest_container_start,
                "owner_names": sorted(owner_names),
                "span_seconds": max(
                    0.0,
                    timeline.duration_between(matches_config_event),
                ),
            }
            if best is None or (
                len(candidate["symptoms"]),
                candidate["config_time"],
            ) > (
                len(best["symptoms"]),
                best["config_time"],
            ):
                best = candidate

        return best

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, events, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, events, context)
        if candidate is None:
            raise ValueError("ConfigMapRolloutDrift explain() called without match")

        pod_name = self._pod_name(pod)
        namespace = self._pod_namespace(pod)
        cm_name = candidate["configmap_name"]
        controller_names = [
            f"{controller['kind']}:{controller['name']}"
            for controller in candidate["controllers"]
        ]
        controller_display = ", ".join(controller_names) or "workload controller"
        config_time = candidate["config_time"].isoformat()

        evidence = [
            f"ConfigMap '{cm_name}' changed at {config_time} after Pod {namespace}/{pod_name} and its containers had already started",
            "Pod consumes the ConfigMap through restart-required surfaces: "
            + "; ".join(candidate["surfaces"]),
            "No controller rollout, pod-template restart annotation, or replacement Pod event was observed after the ConfigMap change",
            f"Workload still appears to be served by {controller_display}",
        ]
        if not candidate["checksum_present"]:
            evidence.append(
                "No config checksum/reloader annotation was found on the matching controller pod template"
            )
        if candidate["symptoms"]:
            latest_symptom = candidate["symptoms"][-1]
            evidence.append(
                f"Pod symptoms continued after the config change: {self._reason(latest_symptom)} - {self._message(latest_symptom)}"
            )
        if candidate["span_seconds"] > 0:
            evidence.append(
                f"Config update and related pod signals span {candidate['span_seconds'] / 60.0:.1f} minutes in the timeline"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONFIGMAP_CHANGED",
                    message=f"ConfigMap '{cm_name}' was updated after the current Pod started",
                    role="configuration_context",
                ),
                Cause(
                    code="POD_TEMPLATE_NOT_ROLLED",
                    message="The workload controller did not create a new pod template revision after the ConfigMap changed",
                    role="controller_root",
                    blocking=False,
                ),
                Cause(
                    code="POD_RUNNING_STALE_CONFIG",
                    message="The running Pod still uses configuration resolved at its previous start time",
                    role="configuration_intermediate",
                ),
                Cause(
                    code="CONFIG_DRIFT_SYMPTOM",
                    message="Application symptoms after the ConfigMap change are consistent with stale rollout drift rather than the new config being applied",
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"configmap:{cm_name}": [
                f"Changed at {config_time}",
                "Referenced through restart-required pod configuration",
            ],
            f"pod:{pod_name}": [
                "Pod was already running before the ConfigMap changed",
                "No replacement Pod start was observed after the ConfigMap change",
            ],
        }
        for controller in candidate["controllers"]:
            object_evidence[f"{controller['kind']}:{controller['name']}"] = [
                "Controller pod template did not show a rollout/restart timestamp after the ConfigMap update"
            ]

        return {
            "root_cause": "ConfigMap changed but workload rollout did not pick up the new config",
            "confidence": 0.94 if candidate["controllers"] else 0.89,
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Deployment or controller pod template does not include a ConfigMap checksum annotation",
                "Reloader/GitOps automation failed to patch the pod template after the ConfigMap changed",
                "A manual ConfigMap edit was applied without a rollout restart",
                "ConfigMap is consumed through environment variables or subPath, which requires Pod recreation to take effect",
            ],
            "suggested_checks": [
                f"kubectl describe configmap {cm_name} -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl rollout history deployment,statefulset,daemonset -n "
                + namespace,
                "Compare Pod start times with ConfigMap managedFields/update events",
                "Add a checksum/config annotation or run a controlled rollout restart after ConfigMap changes",
            ],
        }
