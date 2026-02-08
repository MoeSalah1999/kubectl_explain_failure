from kubectl_explain_failure.engine import normalize_context


class TestPVCNormalization:
    def test_kubernetes_pvc_object(self):
        """
        Real Kubernetes-shaped PVC object should normalize correctly.
        """
        pvc = {
            "metadata": {"name": "mypvc"},
            "status": {"phase": "Pending"},
        }
        context = {"pvc": pvc}
        norm = normalize_context(context)

        # Should set canonical keys
        assert norm["pvc_unbound"] is True
        assert norm["blocking_pvc"] == pvc
        assert norm["pvc"] == pvc
        # Should preserve object-graph mapping
        assert norm["objects"]["pvc"]["mypvc"] == pvc

    def test_legacy_pvc_stub_string_status(self):
        """
        Minimal stub PVC with string status should normalize correctly.
        """
        pvc = {"status": "Pending"}
        context = {"pvc": pvc}
        norm = normalize_context(context)

        assert norm["pvc_unbound"] is True
        assert norm["blocking_pvc"] == pvc
        assert norm["pvc"] == pvc
        # Object-graph should include some default name
        assert len(norm["objects"]["pvc"]) == 1
        obj_name = next(iter(norm["objects"]["pvc"]))
        assert norm["objects"]["pvc"][obj_name] == pvc

    def test_bound_pvc(self):
        """
        PVC in Bound phase should not be considered blocking.
        """
        pvc = {"status": {"phase": "Bound"}}
        context = {"pvc": pvc}
        norm = normalize_context(context)

        assert "pvc_unbound" not in norm
        assert "blocking_pvc" not in norm
        assert norm["pvc"] == pvc
        # Object-graph should include PVC
        obj_name = next(iter(norm["objects"]["pvc"]))
        assert norm["objects"]["pvc"][obj_name] == pvc

    def test_list_of_pvcs(self):
        """
        List of PVCs should normalize each correctly.
        """
        pvc_list = [
            {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}},
            {"metadata": {"name": "pvc2"}, "status": "Pending"},
        ]
        context = {"pvc": pvc_list}
        norm = normalize_context(context)

        # The unbound PVC should be detected
        assert norm["pvc_unbound"] is True
        assert norm["blocking_pvc"]["metadata"]["name"] == "pvc2"
        # Both PVCs should be present in object-graph
        assert set(norm["objects"]["pvc"].keys()) == {"pvc1", "pvc2"}

    def test_multiple_pvcs_mixed_bound_pending(self):
        """
        Ensure normalization selects the first unbound PVC as blocking when multiple PVCs exist.
        """
        pvc_list = [
            {"metadata": {"name": "pvc1"}, "status": {"phase": "Bound"}},
            {"metadata": {"name": "pvc2"}, "status": {"phase": "Pending"}},
            {"metadata": {"name": "pvc3"}, "status": {"phase": "Pending"}},
        ]
        context = {"pvc": pvc_list}
        norm = normalize_context(context)

        # blocking PVC is the first pending one
        assert norm["blocking_pvc"]["metadata"]["name"] == "pvc2"
        assert norm["pvc_unbound"] is True
        # All PVCs present in object graph
        assert set(norm["objects"]["pvc"].keys()) == {"pvc1", "pvc2", "pvc3"}
