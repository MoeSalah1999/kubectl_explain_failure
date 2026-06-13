from kubectl_explain_failure.rules.base_rule import FailureRule


class HeadlessServiceSRVRecordMismatch(FailureRule):
    """
    Detects situations where a headless Service is expected to publish
    SRV records for StatefulSet peer discovery but Kubernetes will not
    generate the expected records.

    Real-world failure modes:

    - StatefulSet references wrong serviceName
    - Governing Service is not headless
    - Service selector no longer matches Pod labels
    - Pod absent from Endpoints / EndpointSlice
    - Endpoint hostname differs from StatefulSet DNS identity
    - Service ports are unnamed (SRV records require named ports)
    - Endpoint publication suppressed because Pod is not Ready
    """

    name = "HeadlessServiceSRVRecordMismatch"
    category = "Networking"

    priority = 94
    deterministic = True

    phases = ["Pending", "Running", "Unknown"]

    requires = {
        "objects": [
            "service",
        ]
    }

    def _find_statefulset(self, pod, context):
        objects = context.get("objects", {})
        statefulsets = objects.get("statefulset", {})

        for owner in pod.get("metadata", {}).get("ownerReferences", []):
            if owner.get("kind") == "StatefulSet":
                return statefulsets.get(owner.get("name"))

        return None

    def _labels_match(self, selector, labels):
        if not selector:
            return False

        if not labels:
            return False

        for key, value in selector.items():
            if labels.get(key) != value:
                return False

        return True

    def _pod_ready(self, pod):
        for condition in pod.get("status", {}).get("conditions", []):
            if condition.get("type") == "Ready" and condition.get("status") == "True":
                return True

        return False

    def _service_is_headless(self, service):
        spec = service.get("spec", {})

        cluster_ip = spec.get("clusterIP")
        if cluster_ip == "None":
            return True

        cluster_ips = spec.get("clusterIPs", [])
        if isinstance(cluster_ips, list) and "None" in cluster_ips:
            return True

        return False

    def _service_has_named_ports(self, service):
        ports = service.get("spec", {}).get("ports", [])

        if not ports:
            return False

        return all(bool(port.get("name")) for port in ports)

    def _find_matching_service(
        self,
        statefulset,
        services,
    ):
        service_name = statefulset.get("spec", {}).get("serviceName")

        if not service_name:
            return None

        return services.get(service_name)

    def _endpoint_hostname_set(
        self,
        service_name,
        endpoints,
        endpoint_slices,
    ):
        hostnames = set()

        ep = endpoints.get(service_name)

        if isinstance(ep, dict):
            for subset in ep.get("subsets", []):
                for address in subset.get("addresses", []):
                    hostname = address.get("hostname")
                    if hostname:
                        hostnames.add(hostname)

        for eps in endpoint_slices.values():
            labels = eps.get("metadata", {}).get("labels", {})

            owner_service = labels.get("kubernetes.io/service-name")

            if owner_service != service_name:
                continue

            for endpoint in eps.get("endpoints", []):
                hostname = endpoint.get("hostname")
                if hostname:
                    hostnames.add(hostname)

        return hostnames

    def _pod_present_in_endpoints(
        self,
        pod,
        service_name,
        endpoints,
        endpoint_slices,
    ):
        pod_ip = pod.get("status", {}).get("podIP")

        pod_name = pod.get("metadata", {}).get("name")

        if not pod_ip and not pod_name:
            return False

        ep = endpoints.get(service_name)

        if isinstance(ep, dict):
            for subset in ep.get("subsets", []):

                for addr in subset.get("addresses", []):
                    if addr.get("ip") == pod_ip or addr.get("hostname") == pod_name:
                        return True

                for addr in subset.get("notReadyAddresses", []):
                    if addr.get("ip") == pod_ip or addr.get("hostname") == pod_name:
                        return True

        for eps in endpoint_slices.values():

            labels = eps.get("metadata", {}).get("labels", {})

            if labels.get("kubernetes.io/service-name") != service_name:
                continue

            for endpoint in eps.get("endpoints", []):
                hostname = endpoint.get("hostname")

                if hostname == pod_name:
                    return True

                for address in endpoint.get("addresses", []):
                    if address == pod_ip:
                        return True

        return False

    def matches(
        self,
        pod,
        events,
        context,
    ):
        objects = context.get("objects", {})

        services = objects.get("service", {})

        endpoints = objects.get("endpoints", {})

        endpoint_slices = objects.get("endpointslice", {})

        statefulset = self._find_statefulset(
            pod,
            context,
        )

        if not statefulset:
            return False

        service = self._find_matching_service(
            statefulset,
            services,
        )

        if not service:
            return False

        if not self._service_is_headless(service):
            return True

        if not self._service_has_named_ports(service):
            return True

        selector = service.get("spec", {}).get("selector", {})

        pod_labels = pod.get("metadata", {}).get("labels", {})

        if not self._labels_match(
            selector,
            pod_labels,
        ):
            return True

        service_name = service.get("metadata", {}).get("name")

        if not self._pod_present_in_endpoints(
            pod,
            service_name,
            endpoints,
            endpoint_slices,
        ):
            return True

        expected_hostname = pod.get("metadata", {}).get("name")

        hostnames = self._endpoint_hostname_set(
            service_name,
            endpoints,
            endpoint_slices,
        )

        if hostnames and expected_hostname and expected_hostname not in hostnames:
            return True

        publish_not_ready = service.get("spec", {}).get(
            "publishNotReadyAddresses", False
        )

        if not publish_not_ready and not self._pod_ready(pod):
            return True

        return False

    def explain(
        self,
        pod,
        events,
        context,
    ):
        objects = context.get("objects", {})

        services = objects.get("service", {})

        statefulset = self._find_statefulset(
            pod,
            context,
        )

        service = self._find_matching_service(
            statefulset,
            services,
        )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        sts_name = statefulset.get("metadata", {}).get("name", "<unknown>")

        service_name = service.get("metadata", {}).get("name", "<unknown>")

        evidence = []
        causes = []

        if not self._service_is_headless(service):
            evidence.append(f"Service '{service_name}' is not headless")
            causes.append("Governing Service does not use clusterIP=None")

        if not self._service_has_named_ports(service):
            evidence.append(f"Service '{service_name}' exposes unnamed ports")
            causes.append("SRV records require named Service ports")

        selector = service.get("spec", {}).get("selector", {})

        labels = pod.get("metadata", {}).get("labels", {})

        if not self._labels_match(
            selector,
            labels,
        ):
            evidence.append("Service selector does not match Pod labels")
            causes.append("Pod is excluded from endpoint publication")

        publish_not_ready = service.get("spec", {}).get(
            "publishNotReadyAddresses", False
        )

        if not publish_not_ready and not self._pod_ready(pod):
            evidence.append(
                "Pod is not Ready and Service does not publish unready endpoints"
            )
            causes.append("Endpoint omitted from SRV record generation")

        return {
            "root_cause": (
                "Headless Service cannot publish the SRV records "
                "required for StatefulSet peer discovery"
            ),
            "confidence": 0.98,
            "blocking": False,
            "evidence": evidence,
            "likely_causes": causes,
            "suggested_checks": [
                "Verify StatefulSet spec.serviceName references the correct headless Service",
                "Verify Service clusterIP is set to None",
                "Verify all Service ports are named",
                "Verify Service selectors match Pod labels",
                "Inspect EndpointSlices for expected pod hostnames",
                "Run: kubectl get endpointslices -o yaml",
                "Run: kubectl get endpoints -o yaml",
                "Run: kubectl get svc -o yaml",
                "Verify SRV resolution using dig or nslookup",
            ],
            "object_evidence": {
                f"statefulset:{sts_name}": [
                    "StatefulSet depends on headless-Service DNS publication"
                ],
                f"service:{service_name}": [
                    "Service participates in SRV record generation"
                ],
                f"pod:{pod_name}": ["Pod expected to appear in SRV endpoint set"],
            },
        }
