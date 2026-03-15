from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from hypothesis import strategies as st

K8S_PHASES = ["Pending", "Running", "Failed", "Unknown"]
EVENT_REASONS = [
    "FailedScheduling",
    "BackOff",
    "FailedMount",
    "Pulled",
    "Created",
    "Started",
    "NodeNotReady",
]
NOISE_OBJECT_KINDS = [
    "configmap",
    "secret",
    "serviceaccount",
    "node",
    "deployment",
    "statefulset",
]


@dataclass
class K8sSnapshot:
    pod: dict[str, Any]
    events: list[dict[str, Any]]
    context: dict[str, Any]

    def clone(self) -> K8sSnapshot:
        return K8sSnapshot(
            pod=copy.deepcopy(self.pod),
            events=copy.deepcopy(self.events),
            context=copy.deepcopy(self.context),
        )

    def inject(self, noise: dict[str, Any]) -> K8sSnapshot:
        injected = self.clone()

        noise_events = noise.get("events", [])
        if isinstance(noise_events, list):
            injected.events.extend(copy.deepcopy(noise_events))

        noise_objects = noise.get("objects", {})
        if isinstance(noise_objects, dict):
            injected.context.setdefault("objects", {})
            for kind, mapping in noise_objects.items():
                if not isinstance(mapping, dict):
                    continue
                injected.context["objects"].setdefault(kind, {})
                injected.context["objects"][kind].update(copy.deepcopy(mapping))

        return injected

    def as_engine_input(
        self,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
        return (
            copy.deepcopy(self.pod),
            copy.deepcopy(self.events),
            copy.deepcopy(self.context),
        )


_dns_label = st.text(
    alphabet=st.characters(min_codepoint=97, max_codepoint=122),
    min_size=1,
    max_size=10,
)


@st.composite
def _timestamp_z(draw) -> str:
    minute_offset = draw(st.integers(min_value=0, max_value=180))
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute_offset)
    return ts.isoformat().replace("+00:00", "Z")


@st.composite
def event_strategy(draw) -> dict[str, Any]:
    reason = draw(st.sampled_from(EVENT_REASONS))
    event: dict[str, Any] = {
        "reason": reason,
        "message": draw(st.text(max_size=120)),
    }

    if draw(st.booleans()):
        event["lastTimestamp"] = draw(_timestamp_z())

    if draw(st.booleans()):
        event["source"] = {"component": draw(st.sampled_from(["scheduler", "kubelet"]))}

    return event


@st.composite
def pvc_strategy(draw, name: str | None = None) -> dict[str, Any]:
    pvc_name = name or draw(_dns_label)
    phase = draw(st.sampled_from(["Pending", "Bound", "Lost"]))

    pvc = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": pvc_name},
        "status": {"phase": phase},
    }

    if phase == "Bound" and draw(st.booleans()):
        pvc["spec"] = {"volumeName": f"pv-{pvc_name}"}

    return pvc


@st.composite
def pv_strategy(draw, claim_name: str | None = None) -> dict[str, Any]:
    pv_name = f"pv-{draw(_dns_label)}"
    phase = draw(st.sampled_from(["Available", "Bound", "Released", "Failed"]))

    pv = {
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {"name": pv_name},
        "status": {"phase": phase},
    }

    if claim_name and draw(st.booleans()):
        pv["spec"] = {
            "claimRef": {
                "name": claim_name,
                "namespace": "default",
            }
        }

    return pv


@st.composite
def pod_strategy(draw, pvc_names: list[str] | None = None) -> dict[str, Any]:
    pod_name = draw(_dns_label)
    phase = draw(st.sampled_from(K8S_PHASES))

    pod: dict[str, Any] = {
        "metadata": {"name": pod_name, "namespace": "default"},
        "status": {"phase": phase},
        "spec": {"containers": [{"name": "app", "image": "nginx:latest"}]},
    }

    if draw(st.booleans()):
        waiting_reason = draw(st.sampled_from(["CrashLoopBackOff", "ImagePullBackOff"]))
        pod["status"]["containerStatuses"] = [
            {
                "name": "app",
                "state": {"waiting": {"reason": waiting_reason}},
            }
        ]

    claim_names = list(pvc_names or [])
    if claim_names and draw(st.booleans()):
        chosen = draw(
            st.lists(
                st.sampled_from(claim_names),
                min_size=1,
                max_size=min(2, len(claim_names)),
                unique=True,
            )
        )
        pod["spec"]["volumes"] = [
            {
                "name": f"vol-{idx}",
                "persistentVolumeClaim": {"claimName": pvc_name},
            }
            for idx, pvc_name in enumerate(chosen)
        ]

    return pod


@st.composite
def snapshot_strategy(draw) -> K8sSnapshot:
    include_pvc = draw(st.booleans())
    pvc_count = draw(st.integers(min_value=1, max_value=2)) if include_pvc else 0

    pvc_objects: dict[str, dict[str, Any]] = {}
    for _ in range(pvc_count):
        name = draw(_dns_label)
        pvc_obj = draw(pvc_strategy(name=name))
        pvc_objects[name] = pvc_obj

    pod = draw(pod_strategy(pvc_names=list(pvc_objects.keys())))
    events = draw(st.lists(event_strategy(), max_size=20))

    context: dict[str, Any] = {"objects": {}}

    if pvc_objects:
        context["objects"]["pvc"] = copy.deepcopy(pvc_objects)
        unbound = [
            p
            for p in pvc_objects.values()
            if p.get("status", {}).get("phase") != "Bound"
        ]
        if unbound:
            context["pvc_unbound"] = True
            context["blocking_pvc"] = copy.deepcopy(unbound[0])
            context["pvc"] = copy.deepcopy(unbound[0])

    include_pv = draw(st.booleans())
    if include_pv:
        claim_name = next(iter(pvc_objects.keys()), None)
        pv_obj = draw(pv_strategy(claim_name=claim_name))
        context["objects"].setdefault("pv", {})
        context["objects"]["pv"][pv_obj["metadata"]["name"]] = pv_obj

    return K8sSnapshot(pod=pod, events=events, context=context)


@st.composite
def crashloop_snapshot_strategy(draw) -> K8sSnapshot:
    pod_name = draw(_dns_label)
    backoff_count = draw(st.integers(min_value=1, max_value=12))

    pod = {
        "metadata": {"name": pod_name, "namespace": "default"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "app",
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                }
            ],
        },
    }
    events = [
        {"reason": "BackOff", "message": "restart backoff"}
        for _ in range(backoff_count)
    ]

    return K8sSnapshot(pod=pod, events=events, context={})


@st.composite
def pvc_scheduler_snapshot_strategy(draw) -> K8sSnapshot:
    pvc_name = draw(_dns_label)
    pod_name = draw(_dns_label)

    pvc_obj = {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": pvc_name},
        "status": {"phase": "Pending"},
    }

    pod = {
        "metadata": {"name": pod_name, "namespace": "default"},
        "status": {"phase": "Pending"},
        "spec": {
            "containers": [{"name": "app", "image": "nginx:latest"}],
            "volumes": [
                {
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": pvc_name},
                }
            ],
        },
    }

    extra_noise = draw(
        st.lists(
            st.sampled_from(["NodeNotReady", "TaintBasedEviction", "Created"]),
            max_size=8,
        )
    )
    events = [{"reason": "FailedScheduling", "message": "0/3 nodes are available"}] + [
        {"reason": r, "message": f"{r} event"} for r in extra_noise
    ]

    context = {
        "pvc": copy.deepcopy(pvc_obj),
        "objects": {"pvc": {pvc_name: copy.deepcopy(pvc_obj)}},
        "blocking_pvc": copy.deepcopy(pvc_obj),
        "pvc_unbound": True,
    }

    return K8sSnapshot(pod=pod, events=events, context=context)


@st.composite
def malformed_snapshot_strategy(draw) -> K8sSnapshot:
    pod_name = draw(_dns_label)
    phase = draw(st.sampled_from(["Pending", "Running", "Unknown"]))

    pod = {
        "metadata": {"name": pod_name, "namespace": "default"},
        "status": {"phase": phase},
    }

    minimal_event = st.fixed_dictionaries(
        {},
        optional={
            "reason": st.one_of(st.none(), st.sampled_from(EVENT_REASONS)),
            "message": st.one_of(st.none(), st.text(max_size=120)),
            "lastTimestamp": st.one_of(
                st.none(),
                st.sampled_from(
                    [
                        "2024-01-01T00:00:00Z",
                        "not-a-timestamp",
                        "",
                    ]
                ),
            ),
            "source": st.one_of(
                st.none(),
                st.text(max_size=20),
                st.fixed_dictionaries({"component": st.text(max_size=20)}),
            ),
        },
    )
    events = draw(st.lists(minimal_event, max_size=20))

    return K8sSnapshot(pod=pod, events=events, context={})


@st.composite
def unrelated_noise(draw) -> dict[str, Any]:
    count = draw(st.integers(min_value=0, max_value=8))
    noise: dict[str, Any] = {"objects": {}}

    for i in range(count):
        kind = draw(st.sampled_from(NOISE_OBJECT_KINDS))
        name = f"{kind}-noise-{i}"
        noise["objects"].setdefault(kind, {})
        noise["objects"][kind][name] = {
            "metadata": {"name": name, "namespace": "default"}
        }

    return noise


@st.composite
def crashloop_oom_snapshot_strategy(draw) -> K8sSnapshot:
    snapshot = draw(crashloop_snapshot_strategy())
    noise = draw(
        st.lists(
            st.sampled_from(["Created", "Pulled", "Started", "NodeNotReady"]),
            max_size=10,
        )
    )
    snapshot.events.extend({"reason": r, "message": f"{r} event"} for r in noise)
    snapshot.pod.setdefault("status", {})
    snapshot.pod["status"]["containerStatuses"] = [
        {
            "name": "app",
            "lastState": {"terminated": {"reason": "OOMKilled"}},
        }
    ]
    return snapshot
