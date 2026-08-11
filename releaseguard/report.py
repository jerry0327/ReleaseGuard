from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult


def write_json_report(result: ScanResult, path: str | Path) -> None:
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
