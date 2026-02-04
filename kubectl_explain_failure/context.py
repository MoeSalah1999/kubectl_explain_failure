import os
from typing import Any

from model import load_json


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


def build_context(args) -> dict[str, Any]:
    context: dict[str, Any] = {}

    # ----------------------------
    # PersistentVolumeClaim(s)
    # ----------------------------
    single_pvc = None
    pvcs: list[dict[str, Any]] = []

    if args.pvc:
        single_pvc = load_json(args.pvc)
        pvcs.append(single_pvc)

    if args.pvcs:
        pvcs.extend(
            load_json(os.path.join(args.pvcs, f))
            for f in os.listdir(args.pvcs)
            if f.endswith(".json")
        )

    if pvcs:
        context["pvcs"] = pvcs

        blocking = _select_blocking_pvc(pvcs)
        if blocking:
            context["pvc_unbound"] = True
            context["blocking_pvc"] = blocking

            # Promote single blocking PVC for rule compatibility
            context["pvc"] = blocking

    # ----------------------------
    # Node
    # ----------------------------
    if args.node:
        context["node"] = load_json(args.node)

    # ----------------------------
    # Service / Endpoints
    # ----------------------------
    if args.service:
        context["svc"] = load_json(args.service)

    if args.endpoints:
        context["ep"] = load_json(args.endpoints)

    # ----------------------------
    # Controllers
    # ----------------------------
    if args.statefulsets:
        context["sts"] = [
            load_json(os.path.join(args.statefulsets, f))
            for f in os.listdir(args.statefulsets)
            if f.endswith(".json")
        ]

    if args.daemonsets:
        context["ds"] = [
            load_json(os.path.join(args.daemonsets, f))
            for f in os.listdir(args.daemonsets)
            if f.endswith(".json")
        ]

    return context
