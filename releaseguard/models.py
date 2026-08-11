from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE_BAND = {
    "low": (10, 39),
    "medium": (40, 69),
    "high": (70, 99),
    "critical": (100, 100),
}


def _score_findings(findings: tuple["Finding", ...]) -> int:
    if not findings:
        return 0
    highest = max(findings, key=lambda item: SEVERITY_RANK[item.severity]).severity
    floor, ceiling = SEVERITY_SCORE_BAND[highest]
    return min(ceiling, floor + max(0, len(findings) - 1) * 5)


def _blocked(findings: tuple["Finding", ...], fail_on: str) -> bool:
    threshold = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[finding.severity] >= threshold for finding in findings)


@dataclass(frozen=True)
class Change:
    path: str
    status: str
    old_path: str | None = None
    is_binary: bool = False
    old_mode: str | None = None
    new_mode: str | None = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    path: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReviewEvidence:
    status: str
    required: bool
    required_on: str
    minimum_approvals: int
    repository: str | None = None
    pull_request: int | None = None
    author: str | None = None
    scanned_base_sha: str | None = None
    scanned_head_sha: str | None = None
    observed_base_sha: str | None = None
    observed_head_sha: str | None = None
    approvals: tuple[str, ...] = ()
    stale_approvals: tuple[str, ...] = ()
    self_approvals: tuple[str, ...] = ()
    bot_approvals: tuple[str, ...] = ()
    untrusted_approvals: tuple[str, ...] = ()
    changes_requested: tuple[str, ...] = ()
    detail: str | None = None

    @property
    def approval_count(self) -> int:
        return len(self.approvals)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in (
            "approvals",
            "stale_approvals",
            "self_approvals",
            "bot_approvals",
            "untrusted_approvals",
            "changes_requested",
        ):
            data[key] = list(data[key])
        data["approval_count"] = self.approval_count
        return data


@dataclass(frozen=True)
class ScanResult:
    base: str
    head: str
    findings: tuple[Finding, ...]
    changed_files: int
    fail_on: str
    tool_version: str
    review_evidence: ReviewEvidence | None = None

    @property
    def score(self) -> int:
        return _score_findings(self.findings)

    @property
    def blocked(self) -> bool:
        return _blocked(self.findings, self.fail_on)

    @property
    def decision(self) -> str:
        return "BLOCK" if self.blocked else "PASS"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 2,
            "tool": {"name": "ReleaseGuard", "version": self.tool_version},
            "base": self.base,
            "head": self.head,
            "decision": self.decision,
            "risk_score": self.score,
            "fail_on": self.fail_on,
            "changed_files": self.changed_files,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.review_evidence is not None:
            payload["review_evidence"] = self.review_evidence.to_dict()
        return payload


@dataclass(frozen=True)
class NpmProvenanceEvidence:
    status: str
    verifier: str
    npm_version: str | None
    registry: str
    package: str
    version: str
    attempts: int = 1
    manifest_integrity: str | None = None
    tarball_url: str | None = None
    attestation_url: str | None = None
    trusted_publisher_id: str | None = None
    trusted_publisher_oidc_config_id: str | None = None
    statement_type: str | None = None
    predicate_type: str | None = None
    verified_attestation_types: tuple[str, ...] = ()
    publish_attestation_types: tuple[str, ...] = ()
    subject_name: str | None = None
    subject_sha512: str | None = None
    repository: str | None = None
    workflow: str | None = None
    commit_sha: str | None = None
    ref: str | None = None
    builder_id: str | None = None
    invocation_id: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verified_attestation_types"] = list(self.verified_attestation_types)
        data["publish_attestation_types"] = list(self.publish_attestation_types)
        return data


@dataclass(frozen=True)
class NpmVerificationResult:
    package: str
    version: str
    registry: str
    expected_repository: str
    expected_workflow: str
    expected_commit: str
    expected_ref: str | None
    expected_builder: str
    require_trusted_publisher: bool
    findings: tuple[Finding, ...]
    fail_on: str
    tool_version: str
    evidence: NpmProvenanceEvidence

    @property
    def score(self) -> int:
        return _score_findings(self.findings)

    @property
    def blocked(self) -> bool:
        return _blocked(self.findings, self.fail_on)

    @property
    def decision(self) -> str:
        return "BLOCK" if self.blocked else "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "report_type": "npm-provenance",
            "tool": {"name": "ReleaseGuard", "version": self.tool_version},
            "package": {
                "name": self.package,
                "version": self.version,
                "registry": self.registry,
            },
            "expected_identity": {
                "repository": self.expected_repository,
                "workflow": self.expected_workflow,
                "commit_sha": self.expected_commit,
                "ref": self.expected_ref,
                "builder_id": self.expected_builder,
                "require_trusted_publisher": self.require_trusted_publisher,
            },
            "decision": self.decision,
            "risk_score": self.score,
            "fail_on": self.fail_on,
            "findings": [finding.to_dict() for finding in self.findings],
            "evidence": self.evidence.to_dict(),
        }
