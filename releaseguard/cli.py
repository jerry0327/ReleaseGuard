from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .config import load_config
from .git import get_changes, resolve_default_range, rev_parse
from .github_evidence import (
    PullRequestContext,
    collect_review_evidence,
    context_from_event,
    context_with_overrides,
)
from .models import ScanResult
from .npm_provenance import DEFAULT_BUILDER, DEFAULT_REGISTRY, verify_npm_package
from .report import markdown_summary, npm_markdown_summary, write_json_report
from .rules import run_rules, sort_findings
from .sarif import write_npm_sarif_report, write_sarif_report


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


def _workflow_from_environment() -> str | None:
    explicit = os.getenv("RELEASEGUARD_EXPECTED_WORKFLOW")
    if explicit:
        return explicit
    workflow_ref = os.getenv("GITHUB_WORKFLOW_REF")
    repository = os.getenv("GITHUB_REPOSITORY")
    if not workflow_ref:
        return None
    prefix = f"{repository}/" if repository else ""
    remainder = workflow_ref[len(prefix) :] if prefix and workflow_ref.startswith(prefix) else workflow_ref
    path = remainder.split("@", 1)[0]
    marker = ".github/workflows/"
    index = path.find(marker)
    return path[index:] if index >= 0 else None


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
    parser.add_argument("--version", action="version", version=f"ReleaseGuard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a git release delta")
    scan.add_argument("--base", help="base commit SHA or ref")
    scan.add_argument("--head", help="head commit SHA or ref")
    scan.add_argument("--config", default="releaseguard.toml", help="path to TOML policy configuration")
    scan.add_argument("--output", default="releaseguard-report.json", help="JSON evidence report path")
    scan.add_argument("--sarif-output", default="releaseguard.sarif", help="SARIF 2.1.0 report path")
    scan.add_argument("--event", default=os.getenv("GITHUB_EVENT_PATH"), help="GitHub event JSON path")
    scan.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY"), help="GitHub repository in owner/name form")
    scan.add_argument("--pull-request", type=int, help="GitHub pull request number")
    scan.add_argument("--github-api-url", default=os.getenv("GITHUB_API_URL", "https://api.github.com"))
    scan.add_argument(
        "--github-api-version",
        default=os.getenv("RELEASEGUARD_GITHUB_API_VERSION", "2022-11-28"),
        help="GitHub REST API version header",
    )

    npm = sub.add_parser(
        "verify-npm",
        help="cryptographically verify a published npm package and its release identity",
    )
    npm.add_argument("package", help="exact npm package name, for example @scope/name")
    npm.add_argument("--version", dest="package_version", required=True, help="exact SemVer package version")
    npm.add_argument(
        "--repository",
        default=os.getenv("GITHUB_REPOSITORY"),
        help="expected GitHub repository in owner/name form",
    )
    npm.add_argument(
        "--workflow",
        default=_workflow_from_environment(),
        help="expected .github/workflows/*.yml path",
    )
    npm.add_argument(
        "--commit",
        default=os.getenv("GITHUB_SHA"),
        help="expected full 40-character source commit SHA",
    )
    npm.add_argument(
        "--ref",
        dest="expected_ref",
        default=os.getenv("GITHUB_REF"),
        help="optional expected refs/heads/... or refs/tags/... value",
    )
    npm.add_argument(
        "--builder-id",
        default=DEFAULT_BUILDER,
        help="expected SLSA builder identity URI",
    )
    npm.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help="HTTPS npm registry origin",
    )
    npm.add_argument(
        "--allow-token-published-provenance",
        action="store_true",
        help="allow valid provenance without the npm GitHub trusted-publisher marker",
    )
    npm.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default="high",
        help="finding severity that blocks package promotion",
    )
    npm.add_argument("--npm", default=os.getenv("RELEASEGUARD_NPM", "npm"), help="npm executable")
    npm.add_argument("--attempts", type=int, default=1, help="verification attempts for registry propagation")
    npm.add_argument("--retry-delay", type=float, default=5.0, help="seconds between attempts")
    npm.add_argument("--timeout", type=float, default=180.0, help="per-command timeout in seconds")
    npm.add_argument(
        "--output",
        default="releaseguard-npm-report.json",
        help="npm provenance JSON report path",
    )
    npm.add_argument(
        "--sarif-output",
        default="releaseguard-npm.sarif",
        help="npm provenance SARIF 2.1.0 report path",
    )
    return parser


def _context(args: argparse.Namespace) -> PullRequestContext | None:
    event_context = context_from_event(args.event)
    return context_with_overrides(
        event_context,
        repository=args.repository,
        pull_request=args.pull_request,
        actor=os.getenv("GITHUB_ACTOR"),
    )


def scan_command(args: argparse.Namespace) -> int:
    if bool(args.base) != bool(args.head):
        raise ValueError("--base and --head must be provided together")

    if args.base and args.head:
        base_ref, head_ref = args.base, args.head
    else:
        base_ref, head_ref = _event_range(args.event) or resolve_default_range()

    base = rev_parse(base_ref)
    head = rev_parse(head_ref)
    config = load_config(args.config)
    changes = get_changes(base, head)
    findings = run_rules(changes, config, base, head)

    evidence, evidence_findings = collect_review_evidence(
        findings,
        policy=config.review,
        context=_context(args),
        scanned_base_sha=base,
        scanned_head_sha=head,
        token=os.getenv("RELEASEGUARD_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN"),
        api_url=args.github_api_url,
        api_version=args.github_api_version,
    )
    findings = sort_findings([*findings, *evidence_findings])
    result = ScanResult(
        base=base,
        head=head,
        findings=tuple(findings),
        changed_files=len(changes),
        fail_on=config.fail_on,
        tool_version=__version__,
        review_evidence=evidence,
    )

    write_json_report(result, args.output)
    write_sarif_report(result, args.sarif_output)
    summary = markdown_summary(result)
    print(summary, end="")
    _append_step_summary(summary)
    _append_github_output("decision", result.decision)
    _append_github_output("risk-score", str(result.score))
    _append_github_output("findings", str(len(result.findings)))
    _append_github_output("report-path", args.output)
    _append_github_output("sarif-path", args.sarif_output)
    return 2 if result.blocked else 0


def verify_npm_command(args: argparse.Namespace) -> int:
    missing = [
        flag
        for flag, value in (
            ("--repository", args.repository),
            ("--workflow", args.workflow),
            ("--commit", args.commit),
        )
        if not value
    ]
    if missing:
        raise ValueError(
            "verify-npm requires " + ", ".join(missing) + " (or the corresponding GitHub Actions environment values)"
        )

    result = verify_npm_package(
        args.package,
        args.package_version,
        expected_repository=args.repository,
        expected_workflow=args.workflow,
        expected_commit=args.commit,
        expected_ref=args.expected_ref or None,
        expected_builder=args.builder_id,
        registry=args.registry,
        require_trusted_publisher=not args.allow_token_published_provenance,
        fail_on=args.fail_on,
        npm_executable=args.npm,
        attempts=args.attempts,
        retry_delay=args.retry_delay,
        timeout=args.timeout,
    )
    write_json_report(result, args.output)
    write_npm_sarif_report(result, args.sarif_output)
    summary = npm_markdown_summary(result)
    print(summary, end="")
    _append_step_summary(summary)
    _append_github_output("decision", result.decision)
    _append_github_output("risk-score", str(result.score))
    _append_github_output("findings", str(len(result.findings)))
    _append_github_output("report-path", args.output)
    _append_github_output("sarif-path", args.sarif_output)
    _append_github_output("cryptographic-status", result.evidence.status)
    _append_github_output("observed-repository", result.evidence.repository or "")
    _append_github_output("observed-workflow", result.evidence.workflow or "")
    _append_github_output("observed-commit", result.evidence.commit_sha or "")
    return 2 if result.blocked else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return scan_command(args)
        if args.command == "verify-npm":
            return verify_npm_command(args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ReleaseGuard error: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
