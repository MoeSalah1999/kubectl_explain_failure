from typing import Any


def build_relations(
    pod: dict[str, Any], context: dict[str, Any]
) -> dict[str, list[str]]:
    """
    Build a directed relationship graph between Kubernetes objects.
    """
    relations: dict[str, list[str]] = {}

    pod_name = pod.get("metadata", {}).get("name", "<unknown>")
    pod_id = f"pod:{pod_name}"
    relations[pod_id] = []

    # PVC → Pod (object graph)
    for pvc in context.get("objects", {}).get("pvc", {}).values():
        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")
        pvc_id = f"pvc:{pvc_name}"
        relations.setdefault(pvc_id, [])
        relations[pvc_id].append(pod_id)

    # Owner → Pod (ReplicaSet / StatefulSet / DaemonSet)
    owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
    for ref in owner_refs:
        owner_kind = ref.get("kind", "").lower()
        owner_name = ref.get("name", "<unknown>")
        owner_id = f"{owner_kind}:{owner_name}"
        relations.setdefault(owner_id, [])
        relations[owner_id].append(pod_id)

    # Node → Pod
    if "node" in context:
        node_name = context["node"].get("metadata", {}).get("name", "<unknown>")
        node_id = f"node:{node_name}"
        relations.setdefault(node_id, [])
        relations[node_id].append(pod_id)

    return relations
