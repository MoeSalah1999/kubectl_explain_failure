"""
# kubectl-explain-failure

A small, read-only diagnostic tool that explains **why a Kubernetes Pod is failing** by
correlating Pod status and Events into a human-readable explanation.

## Problem
Kubernetes exposes raw signals (Pod status, Events), but operators still have to manually
interpret *why* something failed. This tool demonstrates how causal explanations can be
constructed from existing Kubernetes data without modifying the cluster.

## What this tool does
- Reads a Pod JSON and its associated Events JSON
- Applies simple, explicit heuristics
- Produces a structured explanation with evidence and suggested checks

## What this tool does NOT do
- No cluster access required
- No controllers, CRDs, or API changes
- No automatic remediation
- No ML or prediction

## Usage

```bash
python explain_failure.py \
  --pod fixtures/pending_pod.json \
  --events fixtures/failed_scheduling_events.json
```

## Supported failure patterns (initial)
- Pending Pods due to FailedScheduling
- ImagePullBackOff / ErrImagePull
- CrashLoopBackOff (BackOff events)

## Design notes
- File-based input keeps the tool easy to test and review
- Heuristics are explicit and readable by design
- Intended as a foundation for future kubectl plugin work

## Future work
- Live cluster mode using kubectl or Kubernetes client
- Additional heuristics
- Structured output (JSON / YAML)
- kubectl plugin wrapper

License: MIT
"""
