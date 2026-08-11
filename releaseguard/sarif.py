from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .models import Finding, NpmVerificationResult, ScanResult

_LEVEL = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
_SECURITY_SEVERITY = {"low": "2.0", "medium": "5.0", "high": "8.0", "critical": "9.8"}


def _rule(finding: Finding) -> dict[str, Any]:
    help_text = finding.detail
    if finding.remediation:
        help_text += f" Remediation: {finding.remediation}"
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.detail},
        "help": {"text": help_text},
        "properties": {
            "precision": "high",
            "problem.severity": finding.severity,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "tags": ["security", "supply-chain", "release"],
        },
    }


def _fingerprint(finding: Finding, *, context: str = "") -> str:
    # Preserve the established releaseguard/v1 input exactly. npm findings use
    # a separate fingerprint namespace and prepend package identity context.
    parts = (finding.rule_id, finding.path or "", finding.title, finding.detail)
    if context:
        parts = (context, *parts)
    material = "\0".join(parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _result(finding: Finding) -> dict[str, Any]:
    message = finding.detail
    if finding.remediation:
        message += f" Remediation: {finding.remediation}"
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "partialFingerprints": {"releaseguard/v1": _fingerprint(finding)},
        "properties": {"severity": finding.severity},
    }
    if finding.path:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"}
                }
            }
        ]
    return result


def sarif_payload(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, Finding] = {}
    for finding in result.findings:
        rules.setdefault(finding.rule_id, finding)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReleaseGuard",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/jerry0327/ReleaseGuard",
                        "rules": [_rule(rules[key]) for key in sorted(rules)],
                    }
                },
                "automationDetails": {"id": "releaseguard/default"},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "properties": {
                    "decision": result.decision,
                    "riskScore": result.score,
                    "base": result.base,
                    "head": result.head,
                },
                "results": [_result(finding) for finding in result.findings],
            }
        ],
    }


def _npm_purl(package: str, version: str) -> str:
    encoded = quote(package, safe="/")
    return f"pkg:npm/{encoded}@{version}"


def _npm_result(
    finding: Finding,
    *,
    package: str,
    version: str,
) -> dict[str, Any]:
    message = finding.detail
    if finding.remediation:
        message += f" Remediation: {finding.remediation}"
    purl = _npm_purl(package, version)
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": purl}
                }
            }
        ],
        "partialFingerprints": {
            "releaseguard/npm-v1": _fingerprint(
                finding,
                context=f"{package}@{version}",
            )
        },
        "properties": {
            "severity": finding.severity,
            "package": package,
            "version": version,
        },
    }


def npm_sarif_payload(result: NpmVerificationResult) -> dict[str, Any]:
    rules: dict[str, Finding] = {}
    for finding in result.findings:
        rules.setdefault(finding.rule_id, finding)
    evidence = result.evidence
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReleaseGuard",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/jerry0327/ReleaseGuard",
                        "rules": [_rule(rules[key]) for key in sorted(rules)],
                    }
                },
                "automationDetails": {"id": "releaseguard/npm-provenance"},
                "properties": {
                    "reportType": "npm-provenance",
                    "decision": result.decision,
                    "riskScore": result.score,
                    "package": result.package,
                    "version": result.version,
                    "registry": result.registry,
                    "cryptographicStatus": evidence.status,
                    "expectedRepository": result.expected_repository,
                    "observedRepository": evidence.repository,
                    "expectedWorkflow": result.expected_workflow,
                    "observedWorkflow": evidence.workflow,
                    "expectedCommit": result.expected_commit,
                    "observedCommit": evidence.commit_sha,
                },
                "results": [
                    _npm_result(
                        finding,
                        package=result.package,
                        version=result.version,
                    )
                    for finding in result.findings
                ],
            }
        ],
    }


def write_sarif_report(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(sarif_payload(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_npm_sarif_report(result: NpmVerificationResult, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(npm_sarif_payload(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
