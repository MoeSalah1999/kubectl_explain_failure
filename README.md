"""
# kubectl-explain-failure

This project explores a gap in Kubernetes diagnostics: the system exposes raw signals but not causal explanations. The tool reads Pod and Event data and applies explicit heuristics to explain why a workload failed. It’s intentionally read-only and file-based to keep scope controlled.

A small, diagnostic tool that explains **why a Kubernetes Pod is failing** by
correlating Pod status and Events into a human-readable explanation.

## Problem
Kubernetes exposes raw signals (Pod status, Events), but operators still have to manually
interpret *why* something failed. This tool demonstrates how causal explanations can be
constructed from existing Kubernetes data without modifying the cluster.

For example:
- A Pod is `Pending`, but the underlying scheduling constraint is not obvious
- A container is restarting, but the root cause is buried in Events or status fields
- Volume or image failures require manual correlation across multiple objects

This tool explores how **causal explanations** can be constructed from existing Kubernetes data alone.

## What this tool does
- Reads Kubernetes objects from JSON files (Pod, Events; optional PVC / Node)
- Applies explicit, rule-based heuristics
- Produces a structured explanation containing:
  - Root cause
  - Evidence
  - Likely causes
  - Suggested next checks
  - Confidence score

The output is deterministic and fully testable.

## What this tool does NOT do
- ❌ No live cluster access
- ❌ No Kubernetes API client
- ❌ No controllers, CRDs, or admission hooks
- ❌ No automatic remediation
- ❌ No machine learning or prediction

This is a **diagnostic explainer**, not a fixer.

## Usage
python explain_failure.py \
  --pod pod.json \
  --events events.json \
  --pvc pvc.json \
  --node node.json

## Supported failure patterns (initial)
- Pending Pods due to FailedScheduling
- ImagePullBackOff / ErrImagePull
- CrashLoopBackOff (BackOff events)
- OOMKilled containers
- FailedMount (volume mount failures)

## Design notes
- Rule-based, not implicit
Each diagnostic is an explicit rule that can be reviewed, tested, and extended.

- Read-only by design
All inputs are files; no cluster mutation or API access is required.

- Deterministic output
The same inputs always produce the same explanation.

- Reviewable architecture
Heuristics are isolated from parsing and output logic.

## Architecture overview

- FailureRule defines a diagnostic contract:
  - matches(...)
  - explain(...)
- Rules are evaluated in order
- The first matching rule produces the explanation
- If no rule matches, a safe default explanation is returned

This structure allows incremental expansion without increasing complexity.

## Future work
- Live cluster mode using kubectl or Kubernetes client
- Additional heuristics
- Structured output (JSON / YAML)
- kubectl plugin wrapper

License: MIT
"""
