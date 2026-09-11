from __future__ import annotations

import argparse
from pathlib import Path

from .core import dissect
from .license_policy import DEFAULT_ALLOWLIST


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opentooltrimmer",
        description="Find the smallest policy-compatible reusable Python capability slice.",
    )
    parser.add_argument("--repo", required=True, help="Local repository path or public GitHub repository URL")
    parser.add_argument("--need", required=True, help="Plain-language capability request")
    parser.add_argument("--intended-use", required=True, help="Human-readable intended reuse context for the receipt")
    parser.add_argument(
        "--invocation-correlation-id",
        required=True,
        help="Opaque invocation correlation to preserve in the native receipt",
    )
    parser.add_argument("--output", default="opentooltrimmer_output", help="Output directory")
    parser.add_argument(
        "--allow-license",
        action="append",
        dest="allow_licenses",
        help=(
            "Policy-allowed SPDX license id. Repeat to replace the default allowlist; "
            "V0.1 complete-document validation limits still apply."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    allowlist = args.allow_licenses or list(DEFAULT_ALLOWLIST)

    try:
        receipt = dissect(
            repo_source=args.repo,
            need=args.need,
            intended_use=args.intended_use,
            output=Path(args.output),
            allowlist=allowlist,
            invocation_correlation_id=args.invocation_correlation_id,
        )
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2

    print(receipt.decision.value)
    if receipt.selected:
        print(f"selected: {receipt.selected.file}::{receipt.selected.name} lines {receipt.selected.line_start}-{receipt.selected.line_end}")
    print(f"reason: {receipt.decision_reason}")
    print(f"receipt: {Path(args.output) / 'receipt.json'}")
    return 0 if receipt.decision.value in {"ACQUIRE", "POINT_ONLY", "HOLD"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
