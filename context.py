import os
from model import load_json

def build_context(args) -> dict:
    context = {}

    if args.pvc:
        context["pvc"] = load_json(args.pvc)

    if args.pvcs:
        context["pvcs"] = [
            load_json(os.path.join(args.pvcs, f))
            for f in os.listdir(args.pvcs)
            if f.endswith(".json")
        ]

    if args.node:
        context["node"] = load_json(args.node)

    if args.service:
        context["svc"] = load_json(args.service)

    if args.endpoints:
        context["ep"] = load_json(args.endpoints)

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
