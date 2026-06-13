from __future__ import annotations

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class ExternalNameDNSLoopRule(FailureRule):
    """
    Detects DNS recursion loops created by Kubernetes ExternalName Services.

    Examples:

        svc-a -> svc-b.default.svc.cluster.local
        svc-b -> svc-a.default.svc.cluster.local

    or

        svc-a -> svc-b
        svc-b -> svc-c
        svc-c -> svc-a

    Real-world impact:
    - SERVFAIL responses
    - DNS lookup timeouts
    - CoreDNS recursion warnings
    - application connection failures

    This rule relies primarily on object graph inspection rather than
    event text matching.
    """

    name = "ExternalNameDNSLoop"
    category = "Networking"

    severity = "High"
    priority = 87
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "service",
        ],
    }

    blocks = [
        "ServiceConnectivityFailure",
        "DNSLookupFailure",
    ]

    DNS_FAILURE_MARKERS = (
        "servfail",
        "server misbehaving",
        "dns lookup timeout",
        "lookup timed out",
        "recursion detected",
        "coredns",
        "loop detected",
        "plugin/loop",
        "too many redirects",
    )

    EXCLUSIONS = (
        "networkpolicy",
        "network policy",
        "tls handshake",
        "x509",
        "certificate",
        "connection refused",
        "connection reset",
    )

    def _event_text(self, event):
        return (f"{event.get('reason', '')} " f"{event.get('message', '')}").lower()

    def _dns_failure_event(self, event):
        text = self._event_text(event)

        if any(marker in text for marker in self.EXCLUSIONS):
            return False

        return any(marker in text for marker in self.DNS_FAILURE_MARKERS)

    def _extract_externalname_graph(self, services):
        """
        Build graph:

            service_fqdn -> target

        Only includes ExternalName services.
        """

        graph = {}

        for svc_name, svc in services.items():

            spec = svc.get("spec", {})

            if spec.get("type") != "ExternalName":
                continue

            target = spec.get("externalName")

            if not target:
                continue

            metadata = svc.get("metadata", {})

            namespace = metadata.get(
                "namespace",
                "default",
            )

            fqdn = f"{svc_name}." f"{namespace}.svc.cluster.local"

            graph[fqdn.lower()] = str(target).lower()

        return graph

    def _find_cycle(self, graph):
        """
        Standard DFS cycle detection.
        """

        visited = set()
        active = set()

        def dfs(node, path):

            if node in active:
                idx = path.index(node)
                return path[idx:] + [node]

            if node in visited:
                return None

            visited.add(node)
            active.add(node)

            nxt = graph.get(node)

            if nxt and nxt in graph:
                cycle = dfs(
                    nxt,
                    path + [nxt],
                )

                if cycle:
                    return cycle

            active.remove(node)
            return None

        for node in graph:

            cycle = dfs(node, [node])

            if cycle:
                return cycle

        return None

    def _detect_externalname_loop(
        self,
        context,
    ):
        services = context.get("objects", {}).get("service", {})

        if not services:
            return None

        graph = self._extract_externalname_graph(services)

        if not graph:
            return None

        cycle = self._find_cycle(graph)

        if not cycle:
            return None

        return {
            "graph": graph,
            "cycle": cycle,
        }

    def _candidate(
        self,
        timeline,
        context,
    ):
        loop_info = self._detect_externalname_loop(context)

        if not loop_info:
            return None

        dns_events = [
            e for e in timeline.events_within_window(20) if self._dns_failure_event(e)
        ]

        return {
            "loop": loop_info,
            "dns_events": dns_events,
        }

    def matches(
        self,
        pod,
        events,
        context,
    ):
        timeline = context.get("timeline")

        if not isinstance(
            timeline,
            Timeline,
        ):
            return False

        return (
            self._candidate(
                timeline,
                context,
            )
            is not None
        )

    def explain(
        self,
        pod,
        events,
        context,
    ):
        timeline = context["timeline"]

        candidate = self._candidate(
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError("ExternalNameDNSLoop explain() called without match")

        cycle = candidate["loop"]["cycle"]

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        namespace = pod.get("metadata", {}).get("namespace", "default")

        cycle_string = " -> ".join(cycle)

        confidence = 0.97

        if candidate["dns_events"]:
            confidence = 0.99

        evidence = [
            ("ExternalName service DNS recursion loop detected"),
            f"Loop path: {cycle_string}",
        ]

        if candidate["dns_events"]:
            evidence.append(candidate["dns_events"][-1].get("message", ""))

        object_evidence = {}

        for node in cycle[:-1]:
            service_name = node.split(".")[0]

            object_evidence[f"service:{service_name}"] = [
                "Participates in ExternalName DNS loop"
            ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="EXTERNALNAME_SERVICE_USED",
                    message=("Service resolution depends on ExternalName aliases"),
                    role="runtime_context",
                ),
                Cause(
                    code="EXTERNALNAME_DNS_LOOP",
                    message=("ExternalName services form a recursive DNS cycle"),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="DNS_RESOLUTION_FAILURE",
                    message=("DNS queries cannot be resolved successfully"),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": ("ExternalName Services form a DNS resolution loop"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Two ExternalName Services reference each other",
                "Circular ExternalName chain exists across namespaces",
                "ExternalName migration introduced recursive aliases",
                "Service rename left stale ExternalName targets",
                "CoreDNS repeatedly follows aliases until recursion is detected",
            ],
            "suggested_checks": [
                "kubectl get svc -A -o yaml",
                "Inspect all ExternalName Services and their externalName targets",
                "Resolve the alias chain manually to identify recursion",
                "Check CoreDNS logs for loop plugin warnings",
                "Replace recursive aliases with direct destinations",
                (f"kubectl describe pod " f"{pod_name} -n {namespace}"),
            ],
        }
