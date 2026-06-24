from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class NodeInodePressureRule(FailureRule):
    """
    Detects pod scheduling and runtime failures caused by inode exhaustion on
    the pod's assigned or candidate node(s).

    Real-world behavior
    -------------------
    Inodes are a finite per-filesystem resource.  When a node exhausts the
    inode pool on its root, container-runtime, or kubelet state filesystem:

    1. **Scheduling is blocked**: the kubelet sets the `InodePressure` node
       condition to True and applies the `node.kubernetes.io/disk-pressure`
       taint (NoSchedule by default).  The scheduler refuses to place new pods
       until the condition clears.

    2. **Running pods are evicted**: kubelet's eviction manager identifies
       InodePressure as a resource signal and begins gracefully evicting pods
       at or below the eviction threshold, starting with BestEffort then
       Burstable workloads.  Events carry reason="Evicting" or "Evicted" with
       a message referencing inodes or nodefs.inodesFree.

    3. **New container creates fail silently**: even when a pod is "Pending"
       on a pressured node, OCI runtime `runc create` or `containerd` can fail
       to unpack layers or write container metadata because the overlay /
       snapshot store has no free inodes.  Events carry reason="Failed" with
       a message mentioning inode, ENOSPC, or "no space left on device" (which
       can mean either block or inode exhaustion).

    4. **Log rotation and tmpfs writes stall**: containers may produce runtime
       errors about being unable to write logs or temp files, even though block
       space is available, because overlay upper-dirs share the root inode pool.

    Inode exhaustion is distinct from disk (block) pressure:
    - `df -h` may show 80 % block usage while `df -i` shows 100 % inode usage.
    - Common culprits: thousands of small files in /tmp or /var/log, leftover
      container image layers after failed pulls, many small ConfigMap/Secret
      projection directories, or pid-per-file logging runtimes (journald, Java
      GC logs, Prometheus WAL files).

    Signal sources
    --------------
    - Node condition  InodePressure=True.
    - Node taint      node.kubernetes.io/disk-pressure.
    - Kubernetes events with reason=FailedScheduling containing "inode" or
      "insufficient inodes".
    - Kubernetes events with reason=Evicting / Evicted / Preempting where the
      message references inodes, nodefs.inodesFree, or imagefs.inodesFree.
    - Kubelet events with reason=Failed / OOMKilling / BackOff where the
      message references inode, ENOSPC, or "no space left on device" in
      conjunction with inode markers in the broader event window.
    - Kubelet node-level events reason=NodeHasInodePressure,
      reason=NodeHasDiskPressure (older kubelet versions conflate the two).

    Exclusions
    ----------
    - Pure block-space exhaustion without any inode-specific markers (handled
      by NodeDiskPressure).
    - OOM kills without inode context (OOMKilled rule).
    - Image-pull failures where the error is certificate / network-related.
    - Scheduling failures caused by insufficient CPU, memory, or missing
      tolerations.
    """

    name = "NodeInodePressure"
    category = "Node"
    severity = "High"
    priority = 75
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline", "node_conditions"],
        "optional_objects": ["node"],
    }

    blocks = [
        "NodeDiskPressure",
        "InsufficientResource",
    ]

    # ------------------------------------------------------------------ #
    # Tuning                                                               #
    # ------------------------------------------------------------------ #

    WINDOW_MINUTES = 30

    # Minimum cumulative event occurrences required to fire when the node
    # condition is NOT present (guards against transient one-off messages).
    MIN_OCCURRENCES_WITHOUT_CONDITION = 2

    # ------------------------------------------------------------------ #
    # Node condition / taint identifiers                                  #
    # ------------------------------------------------------------------ #

    INODE_CONDITION_TYPE = "InodePressure"
    DISK_PRESSURE_CONDITION_TYPE = "DiskPressure"  # older kubelets reuse this

    INODE_PRESSURE_TAINT_KEY = "node.kubernetes.io/disk-pressure"
    INODE_PRESSURE_TAINT_KEY_ALT = "node.kubernetes.io/inode-pressure"

    # ------------------------------------------------------------------ #
    # Event reason sets                                                   #
    # ------------------------------------------------------------------ #

    # Scheduler-emitted reasons.
    SCHEDULING_REASONS = {
        "failedscheduling",
    }

    # Kubelet-emitted eviction reasons.
    EVICTION_REASONS = {
        "evicting",
        "evicted",
        "preempting",
    }

    # Kubelet-emitted pressure-state-change reasons (node-level events).
    PRESSURE_STATE_REASONS = {
        "nodehaspressure",
        "nodehasinodepressure",
        "nodehasdiskpressure",
        "nodeinodepressure",
        "evictionthresholdmet",
    }

    # Runtime / container-level failure reasons.
    RUNTIME_FAILURE_REASONS = {
        "failed",
        "backoff",
        "failedcreatepodsandbox",
        "failedcreatecontainer",
    }

    # Events whose presence after the last failure indicates self-healing.
    RECOVERY_REASONS = {
        "NodeHasNoDiskPressure",
        "NodeHasNoInodePressure",
        "ScheduledSuccessfully",
        "Scheduled",
        "Started",
        "Created",
        "Pulled",
    }

    # ------------------------------------------------------------------ #
    # Message markers                                                      #
    # ------------------------------------------------------------------ #

    # At least one of these must appear in the message for inode attribution.
    INODE_MARKERS = (
        "inode",
        "inodes",
        "inodesfree",
        "imagefs.inodesfree",
        "nodefs.inodesfree",
        "insufficient inodes",
        "no inodes available",
        "inode quota",
        "out of inodes",
    )

    # ENOSPC / "no space left" can mean block OR inode exhaustion.
    # We accept these only when the broader event window also contains an
    # explicit inode marker, or the node condition is confirmed.
    ENOSPC_MARKERS = (
        "no space left on device",
        "enospc",
        "write /dev/termination-log: no space",
    )

    # Markers that indicate a different root cause and should exclude the
    # event from inode attribution.
    EXCLUDED_MARKERS = (
        # Block-space-only messages (no inode vocabulary)
        "diskpressure",
        # CPU / memory scheduling failures
        "insufficient cpu",
        "insufficient memory",
        "insufficient hugepages",
        # Network / pod sandbox errors
        "failed to create pod sandbox",
        "cni plugin not initialized",
        "network plugin is not ready",
        # Image / auth errors
        "failed to pull image",
        "imagepullbackoff",
        "errimagepull",
        "unauthorized",
        "x509:",
        # OOM — separate signal path
        "oomkilled",
        "out of memory",
        # Toleration mismatches — separate rule
        "node(s) had untolerated taint",
        "had taint",
        "no nodes available to schedule",
        # Affinity / topology
        "didn't match pod anti-affinity rules",
        "node(s) didn't match nodeaffinity",
        "node(s) had volume node affinity conflict",
    )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

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

    def _event_reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "").lower()

    def _event_message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _source_host(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("host") or "").lower()
        return ""

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _involved_kind(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("kind") or "").lower()

    def _involved_name(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("name") or "")

    def _involved_namespace(self, event: dict[str, Any]) -> str:
        return str(event.get("involvedObject", {}).get("namespace") or "")

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

    # ------------------------------------------------------------------ #
    # Node-condition probes                                                #
    # ------------------------------------------------------------------ #

    def _node_inode_pressure(self, context: dict[str, Any]) -> bool:
        """
        Returns True only when there is explicit evidence of inode pressure.

        DiskPressure by itself is NOT sufficient because kubelet raises
        DiskPressure for block-space exhaustion, imagefs exhaustion, and inode
        exhaustion. We only attribute inode pressure when inode-specific evidence
        accompanies the condition.
        """

        node_conditions = context.get("node_conditions") or {}

        #
        # 1. Explicit InodePressure condition (preferred)
        #
        val = node_conditions.get(self.INODE_CONDITION_TYPE)
        if isinstance(val, bool):
            return val
        if isinstance(val, str) and val.lower() in ("true", "yes", "1"):
            return True

        #
        # 2. Node objects
        #
        for node_obj in context.get("objects", {}).get("node", {}).values():

            if not isinstance(node_obj, dict):
                continue

            for condition in node_obj.get("status", {}).get("conditions", []):

                ctype = str(condition.get("type") or "")
                status = str(condition.get("status") or "").lower()

                if status != "true":
                    continue

                #
                # Explicit InodePressure
                #
                if ctype == self.INODE_CONDITION_TYPE:
                    return True

                #
                # DiskPressure only counts if its message explicitly mentions inodes.
                #
                if ctype == self.DISK_PRESSURE_CONDITION_TYPE:

                    msg = (
                        str(condition.get("message") or "")
                        + " "
                        + str(condition.get("reason") or "")
                    ).lower()

                    if any(marker in msg for marker in self.INODE_MARKERS):
                        return True

        return False

    def _node_has_inode_taint(self, context: dict[str, Any]) -> bool:
        """
        Returns True when the node carries a disk-pressure or inode-pressure
        NoSchedule/NoExecute taint.
        """
        for node_obj in context.get("objects", {}).get("node", {}).values():
            if not isinstance(node_obj, dict):
                continue
            for taint in node_obj.get("spec", {}).get("taints", []) or []:
                key = str(taint.get("key") or "")
                effect = str(taint.get("effect") or "")
                if key in (
                    self.INODE_PRESSURE_TAINT_KEY,
                    self.INODE_PRESSURE_TAINT_KEY_ALT,
                ):
                    if effect in ("NoSchedule", "NoExecute", "PreferNoSchedule"):
                        return True
        return False

    def _node_allocatable_inodes(
        self, context: dict[str, Any], node_name: str | None
    ) -> tuple[int | None, int | None]:
        """
        Returns (allocatable_inodes, capacity_inodes) from the node object if
        available, or (None, None) if not populated.  Kubelet exposes these via
        node.status.allocatable["inodes"] and node.status.capacity["inodes"]
        starting from Kubernetes 1.16 with the NodefsInodePressure feature gate.
        """
        if not node_name:
            node_objs = list(context.get("objects", {}).get("node", {}).values())
        else:
            node_objs = []
            node = context.get("objects", {}).get("node", {}).get(node_name)
            if isinstance(node, dict):
                node_objs = [node]

        for node_obj in node_objs:
            if not isinstance(node_obj, dict):
                continue
            status = node_obj.get("status", {}) or {}
            allocatable = status.get("allocatable") or {}
            capacity = status.get("capacity") or {}

            def _parse_inodes(raw: Any) -> int | None:
                if raw is None:
                    return None
                try:
                    return int(str(raw).strip().rstrip("k").rstrip("K"))
                except Exception:
                    return None

            alloc = _parse_inodes(
                allocatable.get("inodes") or allocatable.get("hugepages-1Gi")
            )
            cap = _parse_inodes(capacity.get("inodes"))
            # Only return if at least one dimension is present and looks like inodes
            # (inode counts are typically in the millions; skip if it looks like hugepages)
            if alloc is not None or cap is not None:
                return alloc, cap

        return None, None

    # ------------------------------------------------------------------ #
    # Pod scoping                                                          #
    # ------------------------------------------------------------------ #

    def _targets_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved_kind = self._involved_kind(event)
        if involved_kind and involved_kind not in ("pod", "node", ""):
            return False

        pod_name = pod.get("metadata", {}).get("name")
        pod_namespace = pod.get("metadata", {}).get("namespace")

        if involved_kind == "pod":
            if (
                pod_name
                and self._involved_name(event)
                and self._involved_name(event) != pod_name
            ):
                return False
            if (
                pod_namespace
                and self._involved_namespace(event)
                and self._involved_namespace(event) != pod_namespace
            ):
                return False

        return True

    def _event_on_pod_node(self, event: dict[str, Any], node_name: str) -> bool:
        """
        Returns True when the event's source host matches the pod's assigned
        node, or when no node name is known (accept all).
        """
        if not node_name:
            return True
        host = self._source_host(event)
        if host:
            return node_name.lower() in host or host in node_name.lower()
        # Fallback: check involved object for node kind
        if self._involved_kind(event) == "node":
            return self._involved_name(event).lower() == node_name.lower()
        return True

    # ------------------------------------------------------------------ #
    # Event classification                                                 #
    # ------------------------------------------------------------------ #

    def _has_inode_marker(self, text: str) -> bool:
        lc = text.lower()
        return any(m in lc for m in self.INODE_MARKERS)

    def _has_enospc_marker(self, text: str) -> bool:
        lc = text.lower()
        return any(m in lc for m in self.ENOSPC_MARKERS)

    def _is_excluded(self, message: str) -> bool:
        lc = message.lower()
        return any(m in lc for m in self.EXCLUDED_MARKERS)

    def _is_inode_scheduling_event(
        self, event: dict[str, Any], pod: dict[str, Any]
    ) -> bool:
        if self._event_reason(event) not in self.SCHEDULING_REASONS:
            return False
        if not self._targets_pod(event, pod):
            return False
        message = self._event_message(event)
        if self._is_excluded(message):
            return False
        msg = message.lower()

        # Ignore ordinary FailedScheduling messages.
        if not any(marker in msg for marker in self.INODE_MARKERS):
            return False

        return True

    def _is_inode_eviction_event(
        self, event: dict[str, Any], pod: dict[str, Any], node_name: str
    ) -> bool:
        if self._event_reason(event) not in self.EVICTION_REASONS:
            return False
        if not self._targets_pod(event, pod):
            return False
        if not self._event_on_pod_node(event, node_name):
            return False
        message = self._event_message(event)
        if self._is_excluded(message):
            return False
        return self._has_inode_marker(message)

    def _is_node_pressure_event(self, event: dict[str, Any], node_name: str) -> bool:
        """
        Kubelet node-level events signalling InodePressure state transitions.
        These are involvedObject.kind=Node events emitted by the kubelet.
        """
        reason = self._event_reason(event)
        if reason not in self.PRESSURE_STATE_REASONS:
            return False
        if not self._event_on_pod_node(event, node_name):
            return False
        # If involvedObject is a Node, double-check it's the same node.
        if self._involved_kind(event) == "node" and node_name:
            if self._involved_name(event).lower() != node_name.lower():
                return False
        message = self._event_message(event)
        # Accept even without an explicit inode marker when the reason is
        # specific enough (NodeHasInodePressure) to be unambiguous.
        if reason in (
            "nodehasinodepressure",
            "nodeinodepressure",
            "nodehasdiskpressure",
        ):
            return True
        return self._has_inode_marker(message)

    def _is_inode_runtime_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        node_name: str,
        window_has_explicit_inode: bool,
        has_node_condition: bool,
    ) -> bool:
        """
        Runtime / container-level events (Failed, BackOff) where the message
        contains ENOSPC-family markers.  These are only attributed to inode
        exhaustion when:
        - the message itself contains an explicit inode marker, OR
        - the broader window already has an explicit inode event, OR
        - the node condition is confirmed (InodePressure=True).
        """
        if self._event_reason(event) not in self.RUNTIME_FAILURE_REASONS:
            return False
        if not self._targets_pod(event, pod):
            return False
        if not self._event_on_pod_node(event, node_name):
            return False
        message = self._event_message(event)
        if self._is_excluded(message):
            return False
        if self._has_inode_marker(message):
            return True
        if self._has_enospc_marker(message) and (
            window_has_explicit_inode or has_node_condition
        ):
            return True
        return False

    # ------------------------------------------------------------------ #
    # Event collection                                                     #
    # ------------------------------------------------------------------ #

    def _collect_matching_events(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        node_name: str,
        has_node_condition: bool,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Returns a dict of categorised matching events:
        {
            "scheduling": [...],
            "eviction":   [...],
            "pressure":   [...],
            "runtime":    [...],
        }
        """
        recent = self._ordered_recent_events(timeline)

        scheduling: list[dict[str, Any]] = []
        eviction: list[dict[str, Any]] = []
        pressure: list[dict[str, Any]] = []
        # Pre-scan for explicit inode markers across the window to enable
        # ENOSPC→inode promotion in runtime events.
        explicit_inode_in_window = any(
            self._has_inode_marker(self._event_message(e)) for e in recent
        )

        runtime: list[dict[str, Any]] = []

        for event in recent:
            if self._is_inode_scheduling_event(event, pod):
                scheduling.append(event)
            elif self._is_inode_eviction_event(event, pod, node_name):
                eviction.append(event)
            elif self._is_node_pressure_event(event, node_name):
                pressure.append(event)
            elif self._is_inode_runtime_event(
                event, pod, node_name, explicit_inode_in_window, has_node_condition
            ):
                runtime.append(event)

        return {
            "scheduling": scheduling,
            "eviction": eviction,
            "pressure": pressure,
            "runtime": runtime,
        }

    def _recovery_observed(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        node_name: str,
        since: datetime | None,
    ) -> bool:
        """
        Returns True when a recovery event is observed after *since*,
        suggesting the inode pressure resolved itself.
        """
        for event in timeline.events:
            if str(event.get("reason") or "") not in self.RECOVERY_REASONS:
                continue
            if not self._targets_pod(event, pod) and not self._event_on_pod_node(
                event, node_name
            ):
                continue
            event_at = self._event_time(event)
            if since is None or event_at is None or event_at >= since:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Candidate resolution                                                 #
    # ------------------------------------------------------------------ #

    def _best_candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        node_name: str = str(pod.get("spec", {}).get("nodeName") or "")
        has_node_condition = self._node_inode_pressure(context)
        has_taint = self._node_has_inode_taint(context)

        categorised = self._collect_matching_events(
            pod, timeline, node_name, has_node_condition
        )

        # Never diagnose inode pressure from generic scheduling failures.
        # We require inode-specific evidence unless the node explicitly reports
        # InodePressure.
        #
        has_inode_events = (
            categorised["pressure"]
            or categorised["runtime"]
            or categorised["eviction"]
            or categorised["scheduling"]
        )

        if not has_node_condition and not has_inode_events:
            return None

        all_matching: list[dict[str, Any]] = (
            categorised["scheduling"]
            + categorised["eviction"]
            + categorised["pressure"]
            + categorised["runtime"]
        )

        # If neither a node condition nor any matching event is found, bail.
        if not all_matching and not has_node_condition and not has_taint:
            return None

        # Require a minimum number of event occurrences when the node
        # condition / taint is absent, to avoid false positives from a single
        # transient ENOSPC runtime message.
        total_occurrences = sum(self._occurrences(e) for e in all_matching)
        if not has_node_condition and not has_taint:
            if total_occurrences < self.MIN_OCCURRENCES_WITHOUT_CONDITION:
                return None

        # Suppress if a recovery event was seen after the latest failure.
        if all_matching:
            latest_at = self._event_time(all_matching[-1])
            if self._recovery_observed(pod, timeline, node_name, latest_at):
                return None

        # Compute duration across ALL inode-attributed events.
        def _is_any_inode(e: dict[str, Any]) -> bool:
            return e in all_matching

        duration_seconds = timeline.duration_between(_is_any_inode)

        allocatable_inodes, capacity_inodes = self._node_allocatable_inodes(
            context, node_name or None
        )

        return {
            "node_name": node_name,
            "has_node_condition": has_node_condition,
            "has_taint": has_taint,
            "categorised": categorised,
            "all_matching": all_matching,
            "total_occurrences": total_occurrences,
            "duration_seconds": duration_seconds,
            "allocatable_inodes": allocatable_inodes,
            "capacity_inodes": capacity_inodes,
        }

    # ------------------------------------------------------------------ #
    # Public interface                                                     #
    # ------------------------------------------------------------------ #

    def matches(self, pod: dict, events: list, context: dict) -> bool:
        phase = get_pod_phase(pod)
        if phase not in ("Pending", "Running"):
            return False
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return False
        return self._best_candidate(pod, timeline, context) is not None

    def explain(self, pod: dict, events: list, context: dict) -> dict[str, Any]:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            raise ValueError("NodeInodePressure requires a Timeline context")

        candidate = self._best_candidate(pod, timeline, context)
        if candidate is None:
            raise ValueError(
                "NodeInodePressure.explain() called without a matching candidate"
            )

        pod_meta = pod.get("metadata", {})
        pod_name = pod_meta.get("name", "<unknown>")
        namespace = pod_meta.get("namespace", "default")
        node_name: str = candidate["node_name"]
        categorised: dict[str, list] = candidate["categorised"]
        has_node_condition: bool = candidate["has_node_condition"]
        has_taint: bool = candidate["has_taint"]
        all_matching: list = candidate["all_matching"]
        total_occurrences: int = candidate["total_occurrences"]
        duration_seconds: float = candidate["duration_seconds"]
        allocatable_inodes: int | None = candidate["allocatable_inodes"]
        capacity_inodes: int | None = candidate["capacity_inodes"]

        # Representative messages for each category
        def _last_msg(bucket: str) -> str:
            evs = categorised.get(bucket, [])
            return str(evs[-1].get("message") or "") if evs else ""

        # ------------------------------------------------------------------ #
        # Causal chain                                                         #
        # ------------------------------------------------------------------ #

        # Determine whether this is a scheduling block or a running-pod eviction.
        is_scheduling_block = bool(categorised["scheduling"]) or (
            get_pod_phase(pod) == "Pending" and not categorised["eviction"]
        )
        is_eviction = bool(categorised["eviction"])

        causes = [
            Cause(
                code="NODE_INODE_POOL_EXHAUSTED",
                message=(
                    f"The inode pool on node '{node_name or '<unassigned>'}' is "
                    "exhausted or critically low; no new directory entries can be "
                    "created on the affected filesystem(s)"
                ),
                role="infrastructure_root",
                blocking=True,
            ),
        ]

        if is_scheduling_block:
            causes.append(
                Cause(
                    code="NODE_INODE_PRESSURE_TAINT_BLOCKS_SCHEDULING",
                    message=(
                        "The kubelet applied the InodePressure node condition and "
                        "disk-pressure taint, preventing the scheduler from placing "
                        "new pods on this node"
                    ),
                    role="infrastructure_symptom",
                )
            )
        if is_eviction:
            causes.append(
                Cause(
                    code="POD_EVICTED_BY_INODE_PRESSURE_EVICTION_MANAGER",
                    message=(
                        "The kubelet's eviction manager identified nodefs.inodesFree "
                        "or imagefs.inodesFree below the eviction threshold and is "
                        "evicting pods from the pressured node"
                    ),
                    role="infrastructure_symptom",
                )
            )
        if categorised["runtime"] and not is_scheduling_block and not is_eviction:
            causes.append(
                Cause(
                    code="CONTAINER_RUNTIME_INODE_WRITE_FAILURE",
                    message=(
                        "The container runtime or OCI layer store cannot create new "
                        "files or directories because the inode pool is exhausted on "
                        "the node's container filesystem"
                    ),
                    role="infrastructure_symptom",
                )
            )

        causes.append(
            Cause(
                code="POD_BLOCKED_BY_NODE_INODE_PRESSURE",
                message=(
                    f"Pod '{pod_name}' cannot be scheduled, started, or continues "
                    "running on a node with an exhausted inode pool"
                ),
                role="workload_symptom",
            )
        )

        chain = CausalChain(causes=causes)

        # ------------------------------------------------------------------ #
        # Evidence                                                             #
        # ------------------------------------------------------------------ #

        evidence: list[str] = []

        evidence.append(
            f"Pod {namespace}/{pod_name} is {get_pod_phase(pod)} while the "
            f"assigned node '{node_name or '<unassigned>'}' has inode pressure"
        )

        if has_node_condition:
            evidence.append(
                f"Node '{node_name or '<unassigned>'}' condition InodePressure=True "
                "is set by the kubelet"
            )
        if has_taint:
            evidence.append(
                f"Node '{node_name or '<unassigned>'}' carries the "
                f"'{self.INODE_PRESSURE_TAINT_KEY}' taint, blocking new pod scheduling"
            )

        if categorised["pressure"]:
            msg = _last_msg("pressure")
            evidence.append(
                f"Node-level inode pressure event observed: {msg}"
                if msg
                else "Node-level InodePressure event recorded by the kubelet"
            )

        if categorised["scheduling"]:
            evidence.append(
                f"Scheduler could not place pod due to insufficient inodes: "
                f"{_last_msg('scheduling')}"
            )

        if categorised["eviction"]:
            evidence.append(
                f"Pod is being evicted due to inode pressure: "
                f"{_last_msg('eviction')}"
            )

        if categorised["runtime"]:
            evidence.append(
                f"Container runtime reported an inode / ENOSPC write failure: "
                f"{_last_msg('runtime')}"
            )

        if total_occurrences:
            evidence.append(
                f"Observed {total_occurrences} inode-pressure event occurrence(s) "
                f"within the last {self.WINDOW_MINUTES} minutes"
            )

        if duration_seconds:
            evidence.append(
                f"Inode pressure signals have persisted for "
                f"{duration_seconds / 60:.1f} minutes"
            )

        if allocatable_inodes is not None:
            evidence.append(
                f"Node reports {allocatable_inodes:,} allocatable inodes"
                + (f" out of {capacity_inodes:,} total" if capacity_inodes else "")
            )

        evidence = list(dict.fromkeys(evidence))

        # ------------------------------------------------------------------ #
        # Object evidence                                                      #
        # ------------------------------------------------------------------ #

        object_evidence: dict[str, list[str]] = {
            f"pod:{pod_name}": [
                "Pod is blocked by inode exhaustion on its assigned node",
            ]
        }

        if categorised["scheduling"] and _last_msg("scheduling"):
            object_evidence[f"pod:{pod_name}"].append(_last_msg("scheduling"))

        if categorised["eviction"] and _last_msg("eviction"):
            object_evidence[f"pod:{pod_name}"].append(_last_msg("eviction"))

        if node_name:
            node_ev: list[str] = []
            if has_node_condition:
                node_ev.append("Node condition InodePressure=True")
            if has_taint:
                node_ev.append(
                    f"Node taint {self.INODE_PRESSURE_TAINT_KEY} (NoSchedule) is active"
                )
            if categorised["pressure"] and _last_msg("pressure"):
                node_ev.append(_last_msg("pressure"))
            if allocatable_inodes is not None:
                node_ev.append(
                    f"Allocatable inodes: {allocatable_inodes:,}"
                    + (f" / {capacity_inodes:,}" if capacity_inodes else "")
                )
            if node_ev:
                object_evidence[f"node:{node_name}"] = node_ev

        for key, items in object_evidence.items():
            object_evidence[key] = list(dict.fromkeys(items))

        # ------------------------------------------------------------------ #
        # Confidence                                                           #
        # ------------------------------------------------------------------ #

        # Both condition + events → very high certainty.
        if has_node_condition and all_matching:
            confidence = 0.97
        # Condition alone (no events, but e.g. pod hasn't emitted events yet).
        elif has_node_condition:
            confidence = 0.93
        # Explicit inode scheduling / pressure events without the condition.
        elif categorised["scheduling"] or categorised["pressure"]:
            confidence = 0.91
        # Eviction events referencing inodes.
        elif categorised["eviction"]:
            confidence = 0.88
        # Only runtime ENOSPC events, promoted by window context.
        else:
            confidence = 0.80

        # ------------------------------------------------------------------ #
        # Likely causes                                                        #
        # ------------------------------------------------------------------ #

        likely_causes = [
            "Thousands of small files accumulated in /tmp, /var/log, or application "
            "log directories on the node, consuming all available inodes even though "
            "block space appears available",
            "Stale container image layers, overlayfs upper-dir entries, or containerd "
            "snapshot metadata left behind by failed image pulls or container deletes "
            "have exhausted the container runtime filesystem's inode pool",
            "Each mounted ConfigMap or Secret projection creates a separate tmpfs or "
            "overlayfs directory tree; high pod density with many volume mounts can "
            "exhaust inodes on nodes with small filesystem inode ratios",
            "A Java, Go, or Prometheus-based workload is writing a very large number "
            "of small WAL segments, GC log files, or per-metric files (e.g. the "
            "Prometheus 2.x block/chunk layout) that saturate the inode pool",
            "The root filesystem or /var/lib/kubelet was formatted with a low inode "
            "ratio (bytes-per-inode too large), leaving insufficient inodes relative "
            "to the workload file-count profile of the node",
            "Log files or temp files are not being rotated or cleaned up (logrotate, "
            "fluentd/filebeat harvester, or a custom cleanup job is misconfigured or "
            "not running), causing runaway file accumulation",
            "The node's /var/lib/docker or /var/lib/containerd share a filesystem "
            "with the OS root, and image layer proliferation has consumed all inodes "
            "on that shared volume",
        ]

        # ------------------------------------------------------------------ #
        # Suggested checks                                                     #
        # ------------------------------------------------------------------ #

        suggested_checks = [
            f"kubectl describe pod {pod_name} -n {namespace}",
            f"kubectl get events -n {namespace} --field-selector "
            f"involvedObject.name={pod_name}",
        ]

        if node_name:
            suggested_checks += [
                f"kubectl describe node {node_name}",
                "# On the node: df -i  "
                "# Shows inode usage per filesystem — look for 100% IUse%",
                "# On the node: df -h  "
                "# Compare block usage to confirm inode-only exhaustion",
                "# On the node: find /var/lib/kubelet /var/lib/containerd "
                "/var/lib/docker /tmp -xdev -printf '%i\\n' 2>/dev/null | "
                "sort -u | wc -l  "
                "# Count unique inodes consumed by container-runtime directories",
                "# On the node: du --inodes -sx /* 2>/dev/null | sort -rn | head -20"
                "  # Identify top inode consumers",
                "# Prune stopped containers: crictl rmp --all; crictl rmi --prune",
                "# Rotate or delete large log accumulations: "
                "find /var/log -name '*.log' -mtime +7 -delete",
            ]
        else:
            suggested_checks += [
                "Identify the pod's candidate nodes and run: df -i on each node",
                "kubectl get nodes -o wide  # Identify nodes with InodePressure condition",
            ]

        suggested_checks += [
            "kubectl get nodes -o custom-columns="
            "'NAME:.metadata.name,INODE_PRESSURE:.status.conditions[?(@.type==\"InodePressure\")].status'",
            "kubectl get events --all-namespaces --field-selector "
            "reason=Evicted | grep -i inode",
            "Consider resizing the node's root or container-runtime filesystem "
            "with a higher inode density (mkfs.ext4 -i <bytes-per-inode>) "
            "or migrating to a filesystem with dynamic inode allocation (XFS, btrfs)",
        ]

        return {
            "root_cause": (
                "Node inode pool exhaustion is preventing pod scheduling, "
                "triggering eviction, or causing runtime write failures"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": likely_causes,
            "suggested_checks": list(dict.fromkeys(suggested_checks)),
        }
