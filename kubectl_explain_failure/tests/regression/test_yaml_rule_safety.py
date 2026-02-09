from kubectl_explain_failure.loader import YamlFailureRule


def test_yaml_rule_missing_labels_does_not_crash():
    """
    Regression test:
    YAML rule evaluation must NOT raise KeyError when optional
    nested fields (e.g. metadata.labels) are missing.
    """

    rule = YamlFailureRule(
        {
            "name": "LabelsAccessRule",
            "category": "Generic",
            "priority": 10,
            "requires": {"pod": True},
            "if": "pod['metadata']['labels'].get('app') == 'foo'",
            "then": {
                "root_cause": "LabelBasedFailure",
                "confidence": 0.9,
            },
        }
    )

    pod = {
        "metadata": {
            "name": "test-pod"
            # intentionally NO labels
        },
        "status": {},
    }

    # This must not raise
    assert rule.matches(pod, events=[], context={}) is False


def test_yaml_rule_context_node_labels_missing_does_not_crash():
    rule = YamlFailureRule(
        {
            "name": "ContextNodeLabelsRule",
            "category": "Node",
            "priority": 10,
            "requires": {"context": ["node"]},
            "if": "context['node']['metadata']['labels'].get('foo') == 'bar'",
            "then": {"root_cause": "NodeLabelFailure"},
        }
    )

    context = {
        "node": {
            "metadata": {"name": "test-node"}
            # no labels
        }
    }

    assert rule.matches(pod={}, events=[], context=context) is False
