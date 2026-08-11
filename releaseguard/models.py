from __future__ import annotations

from dataclasses import dataclass, asdict
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
class ScanResult:
    base: str
    head: str
    findings: tuple[Finding, ...]
    changed_files: int
    fail_on: str

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
        return {
            "schema_version": 1,
            "base": self.base,
            "head": self.head,
            "decision": self.decision,
            "risk_score": self.score,
            "fail_on": self.fail_on,
            "changed_files": self.changed_files,
            "findings": [f.to_dict() for f in self.findings],
        }
