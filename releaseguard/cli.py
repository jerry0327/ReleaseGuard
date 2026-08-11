from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .config import load_config
from .git import get_changes, resolve_default_range
from .models import ScanResult
from .report import markdown_summary, write_json_report
from .rules import run_rules


def _event_range(path: str | None) -> tuple[str, str] | None:
    if not path:
        return None
    event_path = Path(path)
    if not event_path.exists():
        return None
    try:
        payload = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    pr = payload.get("pull_request") if isinstance(payload, dict) else None
    if isinstance(pr, dict):
        base = pr.get("base", {}).get("sha") if isinstance(pr.get("base"), dict) else None
        head = pr.get("head", {}).get("sha") if isinstance(pr.get("head"), dict) else None
        if isinstance(base, str) and isinstance(head, str):
            return base, head

    if isinstance(payload, dict):
        before, after = payload.get("before"), payload.get("after")
        if isinstance(before, str) and isinstance(after, str) and set(before) != {"0"}:
            return before, after
    return None


def _append_github_output(name: str, value: str) -> None:
    path = os.getenv("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def _append_step_summary(markdown: str) -> None:
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(markdown)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="releaseguard", description="Deterministic release security gate")
    parser.add_argument("--version", action="version", version="ReleaseGuard 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a git release delta")
    scan.add_argument("--base", help="base commit SHA or ref")
    scan.add_argument("--head", help="head commit SHA or ref")
    scan.add_argument("--config", default="releaseguard.toml", help="path to TOML policy configuration")
    scan.add_argument("--output", default="releaseguard-report.json", help="JSON evidence report path")
    scan.add_argument("--event", default=os.getenv("GITHUB_EVENT_PATH"), help="GitHub event JSON path")
    return parser


def scan_command(args: argparse.Namespace) -> int:
    if bool(args.base) != bool(args.head):
        raise ValueError("--base and --head must be provided together")

    if args.base and args.head:
        base, head = args.base, args.head
    else:
        base, head = _event_range(args.event) or resolve_default_range()

    config = load_config(args.config)
    changes = get_changes(base, head)
    findings = run_rules(changes, config, base, head)
    result = ScanResult(
        base=base,
        head=head,
        findings=tuple(findings),
        changed_files=len(changes),
        fail_on=config.fail_on,
    )

    write_json_report(result, args.output)
    summary = markdown_summary(result)
    print(summary, end="")
    _append_step_summary(summary)
    _append_github_output("decision", result.decision)
    _append_github_output("risk-score", str(result.score))
    _append_github_output("findings", str(len(result.findings)))
    _append_github_output("report-path", args.output)
    return 2 if result.blocked else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return scan_command(args)
    except (RuntimeError, ValueError) as exc:
        print(f"ReleaseGuard error: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
