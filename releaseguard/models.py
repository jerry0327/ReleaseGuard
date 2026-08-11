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
        if not self.findings:
            return 0
        highest = max(self.findings, key=lambda item: SEVERITY_RANK[item.severity]).severity
        floor, ceiling = SEVERITY_SCORE_BAND[highest]
        return min(ceiling, floor + max(0, len(self.findings) - 1) * 5)

    @property
    def blocked(self) -> bool:
        threshold = SEVERITY_RANK[self.fail_on]
        return any(SEVERITY_RANK[f.severity] >= threshold for f in self.findings)

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
