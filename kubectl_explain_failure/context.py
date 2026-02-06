import os
from typing import Any

from kubectl_explain_failure.model import load_json


def _register_object(
    context: dict[str, Any],
    kind: str,
    obj: dict[str, Any],
) -> None:
    if not obj:
        return

    name = obj.get("metadata", {}).get("name")
    if not name:
        return

    context.setdefault("objects", {})
    context["objects"].setdefault(kind, {})
    context["objects"][kind][name] = obj


def _is_pvc_unbound(pvc: dict[str, Any]) -> bool:
    """
    Return True if the PVC exists and is not Bound.
    """
    if not pvc:
        return False

    phase = pvc.get("status", {}).get("phase")
    return phase is not None and phase != "Bound"


def _select_blocking_pvc(pvcs: list[dict[str, Any]]) -> dict[str, Any] | None:
    """
    Return the first unbound PVC, or None if all are bound.
    """
    for pvc in pvcs:
        if _is_pvc_unbound(pvc):
            return pvc
    return None


def _extract_node_conditions(node: dict[str, Any]) -> dict[str, str]:
    conditions = {}
    for c in node.get("status", {}).get("conditions", []):
        cond_type = c.get("type")
        status = c.get("status")
        if cond_type and status:
            conditions[cond_type] = status
    return conditions


def build_context(args) -> dict[str, Any]:
    context: dict[str, Any] = {"objects": {}}

    # ----------------------------
    # PersistentVolumeClaim(s)
    # ----------------------------
    pvcs: list[dict[str, Any]] = []

    if args.pvc:
        pvc = load_json(args.pvc)
        pvcs.append(pvc)
        _register_object(context, "pvc", pvc)

    if args.pvcs:
        for f in os.listdir(args.pvcs):
            if f.endswith(".json"):
                pvc = load_json(os.path.join(args.pvcs, f))
                pvcs.append(pvc)
                _register_object(context, "pvc", pvc)

    if pvcs:
        context["pvcs"] = pvcs
        blocking = _select_blocking_pvc(pvcs)
        if blocking:
            context["pvc_unbound"] = True
            context["blocking_pvc"] = blocking
            context["pvc"] = blocking  # legacy compatibility

    # ----------------------------
    # PersistentVolume
    # ----------------------------
    if args.pv:
        pv = load_json(args.pv)
        _register_object(context, "pv", pv)
        context["pv"] = pv

    # ----------------------------
    # StorageClass
    # ----------------------------
    if args.storageclass:
        sc = load_json(args.storageclass)
        _register_object(context, "storageclass", sc)
        context["storageclass"] = sc

    # ----------------------------
    # Node
    # ----------------------------
    if args.node:
        node = load_json(args.node)
        _register_object(context, "node", node)
        context["node"] = node
        context["node_conditions"] = _extract_node_conditions(node)

    # ----------------------------
    # ServiceAccount / Secret
    # ----------------------------
    if args.serviceaccount:
        sa = load_json(args.serviceaccount)
        _register_object(context, "serviceaccount", sa)

    if args.secret:
        secret = load_json(args.secret)
        _register_object(context, "secret", secret)

    # ----------------------------
    # Controllers
    # ----------------------------
    if args.replicaset:
        rs = load_json(args.replicaset)
        _register_object(context, "replicaset", rs)
        context["owner"] = rs

    if args.deployment:
        deploy = load_json(args.deployment)
        _register_object(context, "deployment", deploy)
        context["owner"] = deploy

    if args.statefulsets:
        context["statefulsets"] = []
        for f in os.listdir(args.statefulsets):
            if f.endswith(".json"):
                sts = load_json(os.path.join(args.statefulsets, f))
                context["statefulsets"].append(sts)
                _register_object(context, "statefulset", sts)

    if args.daemonsets:
        context["daemonsets"] = []
        for f in os.listdir(args.daemonsets):
            if f.endswith(".json"):
                ds = load_json(os.path.join(args.daemonsets, f))
                context["daemonsets"].append(ds)
                _register_object(context, "daemonset", ds)

    return context
