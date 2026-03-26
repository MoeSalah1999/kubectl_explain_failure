from kubectl_explain_failure.rules.base.storage.csi_provisioning_failed import (
    CSIProvisioningFailedRule,
)
from kubectl_explain_failure.rules.base.storage.volume_attach_failed import (
    VolumeAttachFailedRule,
)
from kubectl_explain_failure.rules.base.storage.volume_device_conflict import (
    VolumeDeviceConflictRule,
)
from kubectl_explain_failure.rules.compound.storage.csi_plugin_crashloop import (
    CSIPluginCrashLoopRule,
)
from kubectl_explain_failure.rules.compound.storage.pvc_provision_mount_failure import (
    PVCProvisionThenMountFailureRule,
)
from kubectl_explain_failure.rules.temporal.base.storage.repeated_mount_retry import (
    RepeatedMountRetryRule,
)
from kubectl_explain_failure.timeline import build_timeline


def _pod(
    name: str = "app-pod",
    *,
    phase: str = "Pending",
    node_name: str | None = None,
    pvc_name: str | None = "data-pvc",
    labels: dict | None = None,
    crashloop: bool = False,
    container_name: str = "app",
) -> dict:
    pod = {
        "metadata": {"name": name, "labels": labels or {}},
        "spec": {"volumes": []},
        "status": {"phase": phase, "containerStatuses": []},
    }

    if node_name:
        pod["spec"]["nodeName"] = node_name

    if pvc_name:
        pod["spec"]["volumes"].append(
            {"name": "data", "persistentVolumeClaim": {"claimName": pvc_name}}
        )

    if crashloop:
        pod["status"]["containerStatuses"].append(
            {
                "name": container_name,
                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
            }
        )

    return pod


def _context(*, events: list[dict], objects: dict | None = None) -> dict:
    return {
        "timeline": build_timeline(events, relative_to="last_event"),
        "objects": objects or {},
    }


def test_volume_device_conflict_excludes_generic_attach_failure():
    pod = _pod(node_name="node-a")
    events = [
        {
            "reason": "FailedAttachVolume",
            "message": 'Multi-Attach error for volume "pvc-123": Volume is already exclusively attached to one node',
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:00:00Z",
        }
    ]
    context = _context(
        events=events,
        objects={"pvc": {"data-pvc": {"metadata": {"name": "data-pvc"}}}},
    )

    assert VolumeDeviceConflictRule().matches(pod, events, context) is True
    assert VolumeAttachFailedRule().matches(pod, events, context) is False


def test_csi_provisioning_failed_ignores_external_provisioning_only():
    pod = _pod(pvc_name="data-pvc")
    events = [
        {
            "reason": "ExternalProvisioning",
            "message": "Waiting for a volume to be created either by the external provisioner 'ebs.csi.aws.com' or manually by the system administrator",
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:05:00Z",
            "count": 4,
        }
    ]
    context = _context(
        events=events,
        objects={
            "pvc": {
                "data-pvc": {
                    "metadata": {"name": "data-pvc"},
                    "spec": {"storageClassName": "gp3"},
                    "status": {"phase": "Pending"},
                }
            },
            "storageclass": {
                "gp3": {"metadata": {"name": "gp3"}, "provisioner": "ebs.csi.aws.com"}
            },
        },
    )

    assert CSIProvisioningFailedRule().matches(pod, events, context) is False


def test_csi_provisioning_failed_requires_real_failure_signal():
    pod = _pod(pvc_name="data-pvc")
    events = [
        {
            "reason": "ExternalProvisioning",
            "message": "Waiting for a volume to be created either by the external provisioner 'ebs.csi.aws.com' or manually by the system administrator",
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:00:00Z",
        },
        {
            "reason": "ProvisioningFailed",
            "message": 'failed to provision volume with StorageClass "gp3": rpc error: code = DeadlineExceeded desc = context deadline exceeded',
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:02:00Z",
            "count": 3,
        },
    ]
    context = _context(
        events=events,
        objects={
            "pvc": {
                "data-pvc": {
                    "metadata": {"name": "data-pvc"},
                    "spec": {"storageClassName": "gp3"},
                    "status": {"phase": "Pending"},
                }
            },
            "storageclass": {
                "gp3": {"metadata": {"name": "gp3"}, "provisioner": "ebs.csi.aws.com"}
            },
        },
    )

    assert CSIProvisioningFailedRule().matches(pod, events, context) is True


def test_csi_plugin_crashloop_excludes_generic_application_crashloop():
    pod = _pod(name="web-abc", phase="Running", crashloop=True)
    events = [
        {
            "reason": "BackOff",
            "message": 'Back-off restarting failed container "app" in pod "web-abc_default"',
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:03:00Z",
            "count": 5,
        }
    ]
    context = _context(events=events)

    assert CSIPluginCrashLoopRule().matches(pod, events, context) is False


def test_csi_plugin_crashloop_matches_csi_component_pod():
    pod = _pod(
        name="ebs-csi-node-abc",
        phase="Running",
        pvc_name=None,
        labels={"app.kubernetes.io/name": "aws-ebs-csi-driver"},
        crashloop=True,
        container_name="node-driver-registrar",
    )
    events = [
        {
            "reason": "BackOff",
            "message": 'Back-off restarting failed container "node-driver-registrar" in pod "ebs-csi-node-abc_kube-system"',
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:02:00Z",
            "count": 4,
        }
    ]
    context = _context(events=events)

    assert CSIPluginCrashLoopRule().matches(pod, events, context) is True


def test_repeated_mount_retry_uses_event_count_and_duration():
    pod = _pod(node_name="node-a")
    events = [
        {
            "reason": "FailedMount",
            "message": "Unable to attach or mount volumes: unmounted volumes=[data], unattached volumes=[data]: timed out waiting for the condition",
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:00:00Z",
            "count": 2,
        },
        {
            "reason": "FailedMount",
            "message": "Unable to attach or mount volumes: unmounted volumes=[data], unattached volumes=[data]: timed out waiting for the condition",
            "firstTimestamp": "2026-03-25T10:06:00Z",
            "lastTimestamp": "2026-03-25T10:06:00Z",
            "count": 2,
        },
    ]
    context = _context(
        events=events,
        objects={
            "pvc": {
                "data-pvc": {
                    "metadata": {"name": "data-pvc"},
                    "status": {"phase": "Bound"},
                }
            }
        },
    )

    assert RepeatedMountRetryRule().matches(pod, events, context) is True


def test_pvc_provision_then_mount_failure_excludes_permission_denied_and_requires_provisioning():
    pod = _pod(node_name="node-a")
    base_objects = {
        "pvc": {
            "data-pvc": {
                "metadata": {
                    "name": "data-pvc",
                    "annotations": {
                        "volume.kubernetes.io/storage-provisioner": "ebs.csi.aws.com"
                    },
                },
                "spec": {"storageClassName": "gp3", "volumeName": "pvc-123"},
                "status": {"phase": "Bound"},
            }
        },
        "pv": {
            "pvc-123": {
                "metadata": {
                    "name": "pvc-123",
                    "annotations": {
                        "pv.kubernetes.io/provisioned-by": "ebs.csi.aws.com"
                    },
                }
            }
        },
        "storageclass": {
            "gp3": {"metadata": {"name": "gp3"}, "provisioner": "ebs.csi.aws.com"}
        },
    }

    permission_denied_events = [
        {
            "reason": "FailedMount",
            "message": 'MountVolume.SetUp failed for volume "data": mkdir /var/lib/kubelet/pods/123/volumes/kubernetes.io~csi/data/mount: permission denied',
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:00:00Z",
        }
    ]
    generic_mount_events = [
        {
            "reason": "FailedMount",
            "message": "Unable to attach or mount volumes: unmounted volumes=[data], unattached volumes=[data]: timed out waiting for the condition",
            "firstTimestamp": "2026-03-25T10:00:00Z",
            "lastTimestamp": "2026-03-25T10:00:00Z",
        }
    ]

    rule = PVCProvisionThenMountFailureRule()

    assert (
        rule.matches(
            pod,
            permission_denied_events,
            _context(events=permission_denied_events, objects=base_objects),
        )
        is False
    )
    assert (
        rule.matches(
            pod,
            generic_mount_events,
            _context(events=generic_mount_events, objects=base_objects),
        )
        is True
    )
