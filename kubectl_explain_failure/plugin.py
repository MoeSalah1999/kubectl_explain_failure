from __future__ import annotations

import argparse
import sys

from kubectl_explain_failure.cli import main as cli_main


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explain Kubernetes Pod failures (kubectl plugin, live mode)"
    )
    parser.add_argument("pod", help="Pod name")
    parser.add_argument("-n", "--namespace", default="default")
    parser.add_argument("--context", dest="kube_context")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--event-limit", type=int, default=200)
    parser.add_argument("--event-chunk-size", type=int, default=200)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--retry-backoff", type=float, default=0.25)
    parser.add_argument("--format", choices=["text", "json", "yaml"], default="text")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    translated = [
        "kubectl-explain-failure",
        "pod",
        args.pod,
        "--live",
        "--namespace",
        args.namespace,
        "--timeout",
        str(args.timeout),
        "--event-limit",
        str(args.event_limit),
        "--event-chunk-size",
        str(args.event_chunk_size),
        "--retries",
        str(args.retries),
        "--retry-backoff",
        str(args.retry_backoff),
        "--format",
        args.format,
    ]

    if args.kube_context:
        translated += ["--context", args.kube_context]

    if args.kubeconfig:
        translated += ["--kubeconfig", args.kubeconfig]

    if args.verbose:
        translated.append("--verbose")

    sys.argv = translated
    cli_main()


if __name__ == "__main__":
    main()
