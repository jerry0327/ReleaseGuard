from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .models import NpmVerificationResult, ScanResult


class JsonReport(Protocol):
    def to_dict(self) -> dict[str, object]: ...


def write_json_report(result: JsonReport, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def markdown_summary(result: ScanResult) -> str:
    icon = "🛑" if result.blocked else "✅"
    lines = [
        f"## {icon} ReleaseGuard: {result.decision}",
        "",
        f"- Risk score: **{result.score}/100**",
        f"- Findings: **{len(result.findings)}**",
        f"- Changed files: **{result.changed_files}**",
        f"- Blocking threshold: **{result.fail_on}**",
    ]

    evidence = result.review_evidence
    if evidence is not None and (evidence.required or evidence.minimum_approvals > 0):
        lines.extend(
            [
                f"- Review evidence: **{evidence.status}**",
                f"- Independent approvals: **{evidence.approval_count}/{evidence.minimum_approvals}**",
            ]
        )
    lines.append("")

    if not result.findings:
        lines.append("No policy findings were detected in the release delta.")
        return "\n".join(lines) + "\n"

    lines.extend(["| Severity | Rule | Path | Finding |", "|---|---|---|---|"])
    for finding in result.findings:
        path = finding.path or "—"
        title = finding.title.replace("|", "\\|")
        lines.append(f"| {finding.severity.upper()} | `{finding.rule_id}` | `{path}` | {title} |")
    lines.extend(["", "Review the JSON and SARIF evidence reports for details and remediation guidance."])
    return "\n".join(lines) + "\n"


def npm_markdown_summary(result: NpmVerificationResult) -> str:
    icon = "🛑" if result.blocked else "✅"
    evidence = result.evidence
    lines = [
        f"## {icon} ReleaseGuard npm provenance: {result.decision}",
        "",
        f"- Package: **`{result.package}@{result.version}`**",
        f"- Cryptographic evidence: **{evidence.status}**",
        f"- Verifier: **{evidence.verifier}**",
        f"- npm CLI: **{evidence.npm_version or 'unavailable'}**",
        f"- Attempts: **{evidence.attempts}**",
        f"- Risk score: **{result.score}/100**",
        f"- Findings: **{len(result.findings)}**",
        f"- Blocking threshold: **{result.fail_on}**",
        "",
        "### Expected release identity",
        "",
        f"- Repository: `{result.expected_repository}`",
        f"- Workflow: `{result.expected_workflow}`",
        f"- Commit: `{result.expected_commit}`",
        f"- Ref: `{result.expected_ref or 'not constrained'}`",
        f"- Builder: `{result.expected_builder}`",
        "",
    ]

    if evidence.status == "verified":
        lines.extend(
            [
                "### Verified provenance identity",
                "",
                f"- Repository: `{evidence.repository or 'missing'}`",
                f"- Workflow: `{evidence.workflow or 'missing'}`",
                f"- Commit: `{evidence.commit_sha or 'missing'}`",
                f"- Ref: `{evidence.ref or 'missing'}`",
                f"- Builder: `{evidence.builder_id or 'missing'}`",
                f"- Invocation: `{evidence.invocation_id or 'missing'}`",
                f"- Trusted publisher: `{evidence.trusted_publisher_id or 'missing'}`",
                "",
            ]
        )

    if not result.findings:
        lines.append("The published package passed cryptographic attestation verification and expected identity policy.")
        return "\n".join(lines) + "\n"

    lines.extend(["| Severity | Rule | Finding |", "|---|---|---|"])
    for finding in result.findings:
        title = finding.title.replace("|", "\\|")
        lines.append(f"| {finding.severity.upper()} | `{finding.rule_id}` | {title} |")
    lines.extend(
        [
            "",
            "Review the npm provenance JSON and SARIF reports before promoting this package version.",
        ]
    )
    return "\n".join(lines) + "\n"
