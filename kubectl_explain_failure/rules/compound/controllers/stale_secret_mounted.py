from __future__ import annotations

from datetime import datetime
from typing import Any, TypedDict

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class StaleSecretMountedCandidate(TypedDict):
    secret_name: str
    namespace: str
    pod_name: str
    projected_surfaces: list[str]
    secret_update_time: datetime
    pod_start_time: datetime
    latest_container_start: datetime
    rollout_detected: bool
    rotation_events: list[dict[str, Any]]
    symptom_events: list[dict[str, Any]]
    controllers: list[str]
    immutable_secret: bool
    uses_subpath: bool
    span_seconds: float


class StaleSecretMountedRule(FailureRule):
    """
    Detects Pods continuing to use stale Secret content after Secret rotation.

    Real-world behavior:
    - Secret volumes are eventually refreshed by kubelet, but env/envFrom values
      are fixed when the container starts
    - Secret mounts using subPath remain pinned until Pod recreation
    - projected Secret volumes can lag briefly during kubelet sync periods, but
      long-lived stale behavior usually indicates missing rollout/restart logic
    - Deployments/StatefulSets do not automatically restart Pods after Secret
      rotation unless the pod template changes
    - immutable Secrets cannot refresh in-place and require replacement plus
      workload rollout
    """

    name = "StaleSecretMounted"
    category = "Compound"
    priority = 67
    deterministic = True

    phases = ["Running", "CrashLoopBackOff"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["secret"],
        "optional_objects": [
            "deployment",
            "replicaset",
            "statefulset",
            "daemonset",
        ],
    }

    blocks = [
        "SecretRotationNotApplied",
        "CrashLoopAfterSecretRotation",
        "ConfigChangedButPodNotRestarted",
        "SecretVolumeMountFailure",
    ]

    CACHE_KEY = "_stale_secret_mounted_candidate"

    INCIDENT_WINDOW_MINUTES = 60
    MIN_REFRESH_GRACE_SECONDS = 180

    SECRET_UPDATE_REASONS = {
        "Updated",
        "Modified",
        "Patched",
        "Applied",
        "SecretRotation",
        "RotationComplete",
    }

    SYMPTOM_REASONS = {
        "BackOff",
        "CrashLoopBackOff",
        "Unhealthy",
        "Failed",
        "Warning",
    }

    RESTART_ANNOTATIONS = (
        "kubectl.kubernetes.io/restartedAt",
        "reloader.stakater.com/last-reloaded-from",
        "secret.reloader.stakater.com/reload-time",
        "rollout.kubernetes.io/restartedAt",
    )

    CHECKSUM_HINTS = (
        "checksum/secret",
        "secret-hash",
        "checksum-secret",
    )

    def _parse_time(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_time(event.get("lastTimestamp"))
            or self._parse_time(event.get("eventTime"))
            or self._parse_time(event.get("firstTimestamp"))
            or self._parse_time(event.get("timestamp"))
        )

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace") or "default")

    def _pod_name(self, pod: dict[str, Any]) -> str:
        return str(pod.get("metadata", {}).get("name") or "<pod>")

    def _pod_start_time(self, pod: dict[str, Any]) -> datetime | None:
        status = pod.get("status", {}) or {}

        pod_start = self._parse_time(status.get("startTime"))
        if pod_start:
            return pod_start

        starts: list[datetime] = []

        for container_status in status.get("containerStatuses", []) or []:
            running = (container_status.get("state") or {}).get("running") or {}
            started_at = self._parse_time(running.get("startedAt"))
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
                    ts = self._parse_time(section.get(key))
                    if ts:
                        starts.append(ts)

        return max(starts) if starts else self._pod_start_time(pod)

    def _ordered_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        events = timeline.events_within_window(self.INCIDENT_WINDOW_MINUTES)

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

    def _secret_refs(
        self,
        pod: dict[str, Any],
    ) -> dict[str, list[str]]:
        refs: dict[str, list[str]] = {}

        def add(secret_name: str | None, description: str) -> None:
            if not secret_name:
                return

            refs.setdefault(secret_name, [])

            if description not in refs[secret_name]:
                refs[secret_name].append(description)

        spec = pod.get("spec", {}) or {}

        volume_secret_map: dict[str, tuple[str, bool]] = {}

        for volume in spec.get("volumes", []) or []:
            volume_name = str(volume.get("name") or "")

            secret = volume.get("secret") or {}
            if secret.get("secretName"):
                volume_secret_map[volume_name] = (
                    str(secret["secretName"]),
                    False,
                )

            projected = volume.get("projected") or {}
            for source in projected.get("sources", []) or []:
                projected_secret = source.get("secret") or {}
                if projected_secret.get("name"):
                    volume_secret_map[volume_name] = (
                        str(projected_secret["name"]),
                        True,
                    )

        for container_group in (
            "containers",
            "initContainers",
            "ephemeralContainers",
        ):
            for container in spec.get(container_group, []) or []:
                container_name = str(container.get("name") or "<container>")

                for env in container.get("env", []) or []:
                    secret_ref = (env.get("valueFrom") or {}).get("secretKeyRef") or {}

                    add(
                        secret_ref.get("name"),
                        (
                            f"Referenced through env "
                            f"'{env.get('name', '<env>')}' "
                            f"in container '{container_name}' "
                            "(restart-required)"
                        ),
                    )

                for env_from in container.get("envFrom", []) or []:
                    secret_ref = env_from.get("secretRef") or {}

                    add(
                        secret_ref.get("name"),
                        (
                            f"Referenced through envFrom "
                            f"in container '{container_name}' "
                            "(restart-required)"
                        ),
                    )

                for mount in container.get("volumeMounts", []) or []:
                    volume_name = str(mount.get("name") or "")

                    mapped = volume_secret_map.get(volume_name)
                    if mapped is None:
                        continue

                    secret_name, projected = mapped

                    uses_subpath = bool(
                        mount.get("subPath") or mount.get("subPathExpr")
                    )

                    refresh_behavior = (
                        "restart-required" if uses_subpath else "eventual-refresh"
                    )

                    projection_type = (
                        "projected Secret" if projected else "Secret volume"
                    )

                    add(
                        secret_name,
                        (
                            f"Mounted through {projection_type} "
                            f"'{volume_name}' in container "
                            f"'{container_name}' "
                            f"({refresh_behavior})"
                        ),
                    )

        return refs

    def _secret_update_times(
        self,
        secret_name: str,
        secret: dict[str, Any],
        events: list[dict[str, Any]],
        namespace: str,
    ) -> list[tuple[datetime, str]]:
        updates: list[tuple[datetime, str]] = []

        metadata = secret.get("metadata", {}) or {}

        creation = self._parse_time(metadata.get("creationTimestamp"))
        if creation:
            updates.append((creation, "Secret creation timestamp"))

        for field in metadata.get("managedFields", []) or []:
            if not isinstance(field, dict):
                continue

            ts = self._parse_time(field.get("time"))
            manager = str(field.get("manager") or "unknown")

            if ts:
                updates.append((ts, f"managedFields update by {manager}"))

        for event in events:
            involved = event.get("involvedObject")

            if isinstance(involved, dict):
                kind = str(involved.get("kind") or "").lower()
                name = str(involved.get("name") or "")
                event_namespace = str(involved.get("namespace") or namespace)

                if kind and kind != "secret":
                    continue

                if name and name != secret_name:
                    continue

                if event_namespace != namespace:
                    continue

            text = (f"{self._reason(event)} {self._message(event)}").lower()

            if (
                self._reason(event) not in self.SECRET_UPDATE_REASONS
                and "secret" not in text
                and "rotat" not in text
            ):
                continue

            ts = self._event_time(event)

            if ts:
                updates.append((ts, f"timeline event {self._reason(event)}"))

        return sorted(updates, key=lambda item: item[0])

    def _controller_names(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[str]:
        names: list[str] = []

        objects = context.get("objects", {}) or {}

        namespace = self._namespace(pod)

        for kind in (
            "deployment",
            "statefulset",
            "daemonset",
        ):
            for name, obj in (objects.get(kind) or {}).items():
                if not isinstance(obj, dict):
                    continue

                metadata = obj.get("metadata", {}) or {}

                if str(metadata.get("namespace") or "default") != namespace:
                    continue

                selector = (obj.get("spec", {}) or {}).get("selector", {}).get(
                    "matchLabels", {}
                ) or {}

                labels = pod.get("metadata", {}).get("labels", {}) or {}

                if selector and all(labels.get(k) == v for k, v in selector.items()):
                    names.append(f"{kind}:{name}")

        return sorted(set(names))

    def _template_restart_after(
        self,
        controllers: list[str],
        context: dict[str, Any],
        after: datetime,
    ) -> bool:
        objects = context.get("objects", {}) or {}

        for controller in controllers:
            kind, name = controller.split(":", 1)

            obj = (objects.get(kind) or {}).get(name)

            if not isinstance(obj, dict):
                continue

            annotations = (
                (
                    (obj.get("spec", {}) or {}).get("template", {}).get("metadata", {})
                ).get("annotations", {})
            ) or {}

            for key in self.RESTART_ANNOTATIONS:
                ts = self._parse_time(annotations.get(key))
                if ts and ts >= after:
                    return True

        return False

    def _symptoms_after(
        self,
        events: list[dict[str, Any]],
        after: datetime,
        pod_name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        symptoms: list[dict[str, Any]] = []

        for event in events:
            ts = self._event_time(event)

            if ts is None or ts < after:
                continue

            involved = event.get("involvedObject")

            if isinstance(involved, dict):
                if str(involved.get("namespace") or namespace) != namespace:
                    continue

                involved_name = str(involved.get("name") or "")

                if involved_name not in {"", pod_name}:
                    continue

            reason = self._reason(event)

            text = (f"{reason} {self._message(event)}").lower()

            if (
                reason in self.SYMPTOM_REASONS
                or "certificate expired" in text
                or "authentication failed" in text
                or "permission denied" in text
                or "stale secret" in text
                or "token expired" in text
            ):
                symptoms.append(event)

        return symptoms

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> StaleSecretMountedCandidate | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        namespace = self._namespace(pod)
        pod_name = self._pod_name(pod)

        pod_start = self._pod_start_time(pod)
        latest_container_start = self._latest_container_start(pod)

        if pod_start is None or latest_container_start is None:
            return None

        refs = self._secret_refs(pod)

        if not refs:
            return None

        objects = context.get("objects", {}) or {}
        secrets = objects.get("secret", {}) or {}

        if not secrets:
            return None

        ordered_events = self._ordered_events(timeline)

        controllers = self._controller_names(pod, context)

        best: StaleSecretMountedCandidate | None = None

        for secret_name, surfaces in refs.items():
            secret = secrets.get(secret_name)

            if not isinstance(secret, dict):
                continue

            updates = self._secret_update_times(
                secret_name,
                secret,
                ordered_events,
                namespace,
            )

            if not updates:
                continue

            latest_update, _ = updates[-1]

            if latest_update <= latest_container_start:
                continue

            age_seconds = (latest_update - latest_container_start).total_seconds()

            if age_seconds < self.MIN_REFRESH_GRACE_SECONDS:
                continue

            rollout_detected = self._template_restart_after(
                controllers,
                context,
                latest_update,
            )

            if rollout_detected:
                continue

            symptom_events = self._symptoms_after(
                ordered_events,
                latest_update,
                pod_name,
                namespace,
            )

            immutable_secret = bool(secret.get("immutable") is True)

            uses_subpath = any("restart-required" in item for item in surfaces)

            secret_name_lower = secret_name.lower()

            def matches_secret_event(
                event: dict[str, Any],
                secret: str = secret_name_lower,
            ) -> bool:
                return (
                    secret
                    in (f"{self._reason(event)} " f"{self._message(event)}").lower()
                )

            span_seconds = max(
                0.0,
                timeline.duration_between(matches_secret_event),
            )

            candidate: StaleSecretMountedCandidate = {
                "secret_name": secret_name,
                "namespace": namespace,
                "pod_name": pod_name,
                "projected_surfaces": surfaces,
                "secret_update_time": latest_update,
                "pod_start_time": pod_start,
                "latest_container_start": latest_container_start,
                "rollout_detected": rollout_detected,
                "rotation_events": ordered_events,
                "symptom_events": symptom_events,
                "controllers": controllers,
                "immutable_secret": immutable_secret,
                "uses_subpath": uses_subpath,
                "span_seconds": span_seconds,
            }

            if best is None or (
                len(candidate["symptom_events"]),
                candidate["secret_update_time"],
            ) > (
                len(best["symptom_events"]),
                best["secret_update_time"],
            ):
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
            raise ValueError("StaleSecretMounted explain() called without match")

        secret_name = candidate["secret_name"]
        namespace = candidate["namespace"]
        pod_name = candidate["pod_name"]

        secret_update_time = candidate["secret_update_time"].isoformat()

        controller_display = (
            ", ".join(candidate["controllers"]) or "workload controller"
        )

        evidence = [
            (
                f"Secret '{secret_name}' changed at "
                f"{secret_update_time} after Pod "
                f"{namespace}/{pod_name} had already started"
            ),
            (
                "Pod references the Secret through: "
                + "; ".join(candidate["projected_surfaces"])
            ),
            (
                "No controller rollout or pod-template restart "
                "annotation was observed after the Secret update"
            ),
            (f"Workload still appears to be served by " f"{controller_display}"),
        ]

        if candidate["immutable_secret"]:
            evidence.append(
                "Secret is marked immutable, so in-place refresh is impossible without replacement and Pod recreation"
            )

        if candidate["uses_subpath"]:
            evidence.append(
                "At least one Secret mount uses subPath semantics that require Pod restart to observe updates"
            )

        if candidate["symptom_events"]:
            latest = candidate["symptom_events"][-1]

            evidence.append(
                "Application symptoms continued after "
                f"Secret rotation: {self._reason(latest)} - "
                f"{self._message(latest)}"
            )

        if candidate["span_seconds"] > 0:
            evidence.append(
                "Secret rotation and related workload "
                f"signals span "
                f"{candidate['span_seconds'] / 60.0:.1f} "
                "minutes in the timeline"
            )

        chain = CausalChain(
            causes=[
                Cause(
                    code="SECRET_ROTATED",
                    message=(
                        f"Secret '{secret_name}' was updated " "after the Pod started"
                    ),
                    role="configuration_context",
                ),
                Cause(
                    code="WORKLOAD_NOT_RESTARTED",
                    message=(
                        "The workload controller did not roll "
                        "the Pod template after Secret rotation"
                    ),
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_USING_STALE_SECRET",
                    message=(
                        "The running Pod continues using Secret "
                        "data resolved before rotation"
                    ),
                    role="configuration_intermediate",
                ),
                Cause(
                    code="SECRET_DRIFT_SYMPTOMS",
                    message=(
                        "Observed workload behavior is "
                        "consistent with stale Secret usage"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        object_evidence = {
            f"secret:{secret_name}": [
                f"updatedAt={secret_update_time}",
            ],
            f"pod:{pod_name}": [
                ("Pod/container start time predates " "latest Secret rotation"),
                (
                    "No replacement Pod or rollout restart "
                    "was observed after Secret update"
                ),
            ],
        }

        for controller in candidate["controllers"]:
            object_evidence[controller] = [
                (
                    "Controller template does not show a "
                    "restart timestamp newer than the Secret update"
                )
            ]

        return {
            "root_cause": (
                "Secret rotated but the running workload "
                "continued using stale mounted or injected data"
            ),
            "confidence": (0.95 if candidate["controllers"] else 0.90),
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Secret values are injected through env/envFrom, which requires Pod recreation to refresh",
                "Workload lacks checksum annotations or restart automation tied to Secret rotation",
                "Secret volume is mounted through subPath and cannot refresh dynamically",
                "Secret rotation completed but rollout automation failed or was skipped",
                "Immutable Secret was replaced without restarting dependent Pods",
            ],
            "suggested_checks": [
                f"kubectl describe secret {secret_name} -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
                (
                    "kubectl rollout history "
                    "deployment,statefulset,daemonset "
                    f"-n {namespace}"
                ),
                (
                    "Compare Secret managedFields timestamps "
                    "with Pod/container start times"
                ),
                (
                    "Add checksum/secret annotations or "
                    "restart automation after Secret rotation"
                ),
            ],
        }
